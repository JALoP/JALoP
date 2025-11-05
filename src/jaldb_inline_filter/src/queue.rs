use core::clone::Clone;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::Semaphore;

/// a bounded back pressuring queue
/// allows eviction
/// fully async, block producers & consumers
#[derive(Clone)]
pub struct BackPressureQueue<V> {
    capacity: usize,
    queue: Arc<Mutex<HashMap<String, V>>>,
    not_empty: Arc<Notify>,
    semaphore: Arc<Semaphore>,
}

impl<V> BackPressureQueue<V>
where
    V: Clone + Send + Sync + PartialEq + Eq,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: Default::default(),
            not_empty: Default::default(),
            semaphore: Arc::new(Semaphore::new(capacity)),
        }
    }

    pub async fn insert<K: AsRef<str>>(&self, k: K, v: V) -> anyhow::Result<Option<()>> {
        // precheck for dupes, scoped to release the lock while waiting on
        // the semaphore to acquire. other threads need the lock to free capacity
        {
            let queue = self.queue.lock().await;
            if queue.contains_key(k.as_ref()) {
                return Ok(None);
            }
        }

        // blocks until a permit is available
        let permit = self.semaphore.acquire().await?;

        // check for dupe again after getting the permit
        // if it is a dupe the permit is released by scope
        let mut queue = self.queue.lock().await;
        if queue.contains_key(k.as_ref()) {
            return Ok(None);
        }

        // k is not a dupe, so insert and forget the permit
        queue.insert(k.as_ref().to_string(), v);
        permit.forget();

        // notify consumers of content
        self.not_empty.notify_one();

        Ok(Some(()))
    }

    /// remove an entry by its key, returning Some if evicted
    pub async fn evict<K: AsRef<str>>(&self, k: K) -> Option<V> {
        let mut queue = self.queue.lock().await;
        let res = queue.remove(k.as_ref());
        if let Some(_) = res {
            self.semaphore.add_permits(1);
        }
        res
    }

    /// remove all entries with the specified value, returning count of evicted entries
    pub async fn evict_values(&self, v: V) -> usize {
        let mut queue = self.queue.lock().await;
        let original = queue.len();
        queue.retain(|_, existing| v != *existing);
        let evicted = original - queue.len();
        self.semaphore.add_permits(evicted);
        evicted
    }

    // take an item out of the bpq, waiting if empty
    #[cfg(test)]
    async fn take(&self) -> Option<(String, V)> {
        loop {
            // retake the lock every loop iteration
            // if a value is present, take it and free up a permit
            {
                let mut queue = self.queue.lock().await;
                if let Some(k) = queue.keys().next().cloned() {
                    let res = queue.remove(&k);
                    self.semaphore.add_permits(1);
                    return res.map(|v| (k, v));
                }
            }
            // await here while empty, get notified on insert
            self.not_empty.notified().await;
        }
    }

    pub async fn contains<K: AsRef<str>>(&self, k: K) -> bool {
        self.queue.lock().await.contains_key(k.as_ref())
    }

    pub async fn keys(&self) -> Vec<String> {
        self.queue.lock().await.keys().cloned().collect()
    }

    pub async fn len(&self) -> usize {
        self.queue.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.queue.lock().await.is_empty()
    }

    pub async fn is_full(&self) -> bool {
        self.available().await == 0
    }

    /// remaining capacity
    pub async fn available(&self) -> usize {
        self.capacity - self.len().await
    }
}

/// Specialized impl for tracking keys only
impl BackPressureQueue<()> {
    /// Create a new instance of a keys only queue with capacity
    pub fn keys_only(capacity: usize) -> Self {
        Self::new(capacity)
    }

    /// Push a new key into the queue
    pub async fn push<K: AsRef<str>>(&self, k: K) -> anyhow::Result<Option<()>> {
        self.insert(k, ()).await
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use futures_util::future::join_all;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::broadcast;
    use tokio::time::{interval, sleep};

    use super::*;

    // demonstrate that dupes are ignored
    #[tokio::test]
    async fn test_duplicate_push() {
        let q = Arc::new(BackPressureQueue::keys_only(2));
        assert_eq!(q.available().await, 2);
        q.push("foo").await.unwrap();
        assert_eq!(q.available().await, 1);
        q.take().await.unwrap();
        assert_eq!(q.available().await, 2);
        q.push("foo").await.unwrap();
        q.push("foo").await.unwrap();
        assert_eq!(q.available().await, 1);
    }

    // demonstrate that many threads can produce and many threads can evict
    #[tokio::test]
    async fn test_concurrent_evictions() {
        let q = Arc::new(BackPressureQueue::keys_only(7));

        // 123 threads each producing 456 entries concurrently into bpq
        let producers = 123;
        let producing = 456;
        let expected: usize = producers * producing;
        let (tx, _rx) = broadcast::channel(100);

        for producer in 0..producers {
            tokio::spawn({
                let tx = tx.clone();
                let q = q.clone();
                async move {
                    for produced in 0..producing {
                        let k = format!("{producer}-{produced}");
                        q.push(&k).await.unwrap();
                        tx.send(k).unwrap();
                    }
                }
            });
        }

        let actual = Arc::new(AtomicUsize::new(0));

        let evictors = 7;
        let mut evictor_tasks = vec![];
        for _ in 0..evictors {
            let t = tokio::spawn({
                let actual = actual.clone();
                let mut rx = tx.subscribe();
                let q = q.clone();
                async move {
                    while let Ok(k) = rx.recv().await {
                        if let Some(_) = q.evict(k).await {
                            actual.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            });
            evictor_tasks.push(t);
        }

        drop(tx);
        join_all(evictor_tasks).await;
        assert_eq!(expected, actual.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_concurrent_evict_all() {
        let q = BackPressureQueue::new(2);
        q.insert("a", 0).await.unwrap();
        q.insert("b", 0).await.unwrap();
        let insert = tokio::spawn({
            let q = q.clone();
            async move {
                q.insert("c", 1).await.unwrap();
            }
        });
        let cnt = q.evict_values(0).await;
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => assert!(false),
            _ = insert => {}
        }
        assert_eq!(cnt, 2);
        assert_eq!(q.len().await, 1);
    }

    // demonstrate that many threads can produce and many threads can evict
    // produces collisions on push to demonstrate proper lock handling on dupe
    #[tokio::test]
    async fn test_colliding_producers() {
        let q = Arc::new(BackPressureQueue::keys_only(7));

        // 99 threads each producing 99 entries concurrently into bpq
        let producers = 99;
        let producing = 99;

        // broadcast channel alerts all evictors and they race to evict
        let (tx, _rx) = broadcast::channel(42);

        let expected = Arc::new(AtomicUsize::new(0));

        for _ in 0..producers {
            tokio::spawn({
                let expected = expected.clone();
                let tx = tx.clone();
                let q = q.clone();
                async move {
                    for produced in 0..producing {
                        let k = format!("{produced}");
                        // some producers may reproduce a previously evicted nonce
                        // they are only inserted if they are not present
                        if let Ok(Some(_)) = q.push(&k).await {
                            expected.fetch_add(1, Ordering::SeqCst);
                            tx.send(k).unwrap();
                        }
                    }
                }
            });
        }

        let actual = Arc::new(AtomicUsize::new(0));

        // 111 threads evicting from the queue
        let evictors = 111;
        let mut evictor_tasks = vec![];
        for _ in 0..evictors {
            let t = tokio::spawn({
                let actual = actual.clone();
                let mut rx = tx.subscribe();
                let q = q.clone();
                async move {
                    while let Ok(k) = rx.recv().await {
                        if let Some(_) = q.evict(k).await {
                            actual.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            });
            evictor_tasks.push(t);
        }

        drop(tx);
        join_all(evictor_tasks).await;
        assert_eq!(expected.load(Ordering::Relaxed), actual.load(Ordering::Relaxed));
    }

    // demonstrate backpressure while taking from the queue
    #[tokio::test]
    async fn test_back_pressure_take() {
        let q = Arc::new(BackPressureQueue::new(2));
        let q1 = q.clone();

        q.insert("a".to_owned(), 1).await.unwrap();
        q.insert("b".to_owned(), 2).await.unwrap();

        tokio::spawn(async move {
            q1.insert("c", 3).await.unwrap();
            q1.insert("d", 4).await.unwrap();
        });

        assert!(q.contains("a").await);
        assert!(q.contains("b").await);
        assert!(!q.contains("c").await);
        assert!(!q.contains("d").await);

        q.evict("a").await;
        sleep(Duration::from_millis(1)).await;

        assert!(!q.contains("a").await);
        assert!(q.contains("b").await);
        assert!(q.contains("c").await);
        assert!(!q.contains("d").await);

        q.evict("c").await;
        sleep(Duration::from_millis(1)).await;

        assert!(!q.contains("a").await);
        assert!(q.contains("b").await);
        assert!(!q.contains("c").await);
        assert!(q.contains("d").await);
    }

    // demonstrate backpressure when queue is at capacity
    #[tokio::test]
    async fn test_backpressure_full() {
        let q = Arc::new(BackPressureQueue::keys_only(2));

        q.push("a".to_owned()).await.unwrap();
        q.push("b".to_owned()).await.unwrap();
        assert!(q.is_full().await);

        tokio::select! {
            _ = q.push("c".to_owned()) => assert!(false),
            _ = sleep(Duration::from_millis(500)) => assert!(true),
        }

        assert!(q.is_full().await);
        q.take().await.unwrap();
        assert_eq!(q.available().await, 1);

        tokio::select! {
            _ = q.push("c".to_owned()) => assert!(true),
            _ = sleep(Duration::from_millis(500)) => assert!(false),
        }

        assert!(q.is_full().await);
    }

    // demonstrate that take will wait when nothing is available
    #[tokio::test]
    async fn test_take_awaits() {
        let q = Arc::new(BackPressureQueue::keys_only(2));

        let mut timeout = interval(Duration::from_secs(1));
        timeout.tick().await;

        let expected = 42;

        let actual = tokio::spawn({
            let q = q.clone();
            async move {
                let mut actual = 0;
                loop {
                    tokio::select! {
                        _ = timeout.tick() => break,
                        _ = q.take() => actual += 1,
                    }
                }
                actual
            }
        });

        sleep(Duration::from_millis(100)).await;

        tokio::spawn({
            let q = q.clone();
            async move {
                for i in 0..expected {
                    sleep(Duration::from_millis(7)).await;
                    q.push(format!("{i}")).await.unwrap();
                }
            }
        });

        let actual = actual.await.unwrap();
        assert_eq!(expected, actual);
        assert!(q.is_empty().await);
    }

    // demonstrate that evict_all will remove entries that match the specified value
    #[tokio::test]
    async fn test_evict_values() {
        let q = BackPressureQueue::new(2);
        q.insert("a", 0).await.unwrap();
        q.insert("b", 0).await.unwrap();
        let cnt = q.evict_values(0).await;
        assert_eq!(cnt, 2);
        assert_eq!(q.len().await, 0);

        let q = BackPressureQueue::new(2);
        q.insert("a", 0).await.unwrap();
        q.insert("b", 1).await.unwrap();
        let cnt = q.evict_values(0).await;
        assert_eq!(cnt, 1);
        assert_eq!(q.len().await, 1);

        let q = BackPressureQueue::new(3);
        q.insert("a", 0).await.unwrap();
        q.insert("b", 0).await.unwrap();
        q.insert("c", 1).await.unwrap();
        let cnt = q.evict_values(0).await;
        assert_eq!(cnt, 2);
        assert_eq!(q.len().await, 1);
    }
}
