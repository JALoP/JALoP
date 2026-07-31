/***
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//! This module provides the [ActorSystem] and related [ActorContext] functionality.
use crate::actor::{Actor, ActorRef, Protocol, Receiver};
use crate::backend::ActorExecutor;
use crate::path::ActorPath;
use crate::KillRx;
use crate::KillTx;
use crate::{ActorError, ActorSystemError};
use log::trace;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch, RwLock};

#[derive(Clone)]
pub(crate) enum SystemEvent {
    ActorStopped(ActorPath),
}

/// A system is a hierarchical group of [Actor]s
/// The implementation of this type provides methods to create and access running actors
#[derive(Clone)]
pub struct ActorSystem {
    name: String,
    actors: Arc<RwLock<ActorRefMap>>,
    bus: mpsc::UnboundedSender<SystemEvent>,
    kill: KillTx,
    killed: watch::Receiver<bool>,
}

/// A view of the [Actor] instance within the system that provides contextual information about the running actor.
pub struct ActorContext<A>
where
    A: Actor + ?Sized,
{
    pub path: ActorPath,
    pub system: ActorSystem,
    pub(crate) behavior: A::Behavior,
    pub(crate) becomes: Option<A::Behavior>,
    pub(crate) kill: KillTx,
    pub(crate) aref: ActorRef<A>,
}

impl ActorSystem {
    /// Create a new system
    pub fn new(name: &str) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let actors = Arc::new(RwLock::new(ActorRefMap::default()));
        let (kill_tx, _) = broadcast::channel(1);
        let (killed_tx, killed_rx) = watch::channel(false);
        tokio::spawn({
            let system_name = name.to_owned();
            let actors = actors.clone();
            let mut kill_rx = kill_tx.subscribe();
            async move {
                loop {
                    tokio::select! {
                        Some(e) = rx.recv() => {
                            match e {
                                SystemEvent::ActorStopped(path) => {
                                    let mut db = actors.write().await;
                                    trace!("{system_name}-actor-system: removing actor @ {path}");
                                    db.remove(&path);
                                }
                            }
                        }
                        _ = kill_rx.recv() => {
                            trace!("{system_name}-actor-system: killed");
                            break
                        }
                    }
                }
                let _ = killed_tx.send(true);
            }
        });

        Self {
            name: name.to_string(),
            actors,
            bus: tx,
            kill: kill_tx,
            killed: killed_rx,
        }
    }

    pub async fn children_of(&self, path: &ActorPath) -> Vec<ActorPath> {
        let actors = self.actors.read().await;
        actors
            .iter()
            .filter(|(p, _)| p.parent().is_some_and(|p| &p == path))
            .map(|(p, _)| p.clone())
            .collect()
    }

    pub async fn get_actor<A: Actor>(&self, path: &ActorPath) -> Option<ActorRef<A>> {
        let actors = self.actors.read().await;
        actors.get(path).and_then(|r| r.downcast_ref::<ActorRef<A>>().cloned())
    }

    pub async fn get_or_create_actor_path<A, F>(
        &self,
        path: &ActorPath,
        make_actor: F,
    ) -> Result<ActorRef<A>, ActorError>
    where
        A: Actor,
        F: FnOnce() -> A,
    {
        match self.get_actor(path).await {
            Some(a) => Ok(a),
            None => self.create_actor_path(path.clone(), make_actor()).await,
        }
    }

    pub async fn get_or_create_actor<A, F>(&self, path: &str, make_actor: F) -> Result<ActorRef<A>, ActorError>
    where
        A: Actor,
        F: FnOnce() -> A,
    {
        self.get_or_create_actor_path(&path.into(), make_actor).await
    }

    pub async fn create_actor<A: Actor>(&self, name: &str, actor: A) -> Result<ActorRef<A>, ActorError> {
        self.create_actor_path(ActorPath::new(name), actor).await
    }

    pub async fn create_actor_path<A: Actor>(&self, path: ActorPath, actor: A) -> Result<ActorRef<A>, ActorError> {
        self.create_actor_path_impl(path, actor, self.kill.subscribe()).await
    }
    async fn create_actor_path_impl<A: Actor>(
        &self,
        path: ActorPath,
        actor: A,
        kill: KillRx,
    ) -> Result<ActorRef<A>, ActorError> {
        let mut actors = self.actors.write().await;
        if actors.contains_key(&path) {
            return Err(ActorError::ActorExists(path));
        }

        let system = self.clone();
        let (exec, actor_ref) = ActorExecutor::new(path, actor, kill);

        let path = actor_ref.path().clone();
        let any = Box::new(actor_ref.clone());
        actors.insert(path, any);

        // start the executor
        tokio::spawn(async move {
            exec.start(system).await;
        });

        Ok(actor_ref)
    }

    pub(crate) fn publish(&self, e: SystemEvent) -> Result<(), ActorSystemError> {
        self.bus.send(e).map_err(|_| ActorSystemError::SystemEventPublish)
    }

    pub async fn terminate(&self) {
        let _ = self.kill.send(());
    }

    pub async fn await_shutdown(&self) {
        let interval = Duration::from_millis(100);
        while !*self.killed.borrow() {
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn await_shutdown_with_timeout(&self, timeout: Duration) -> Result<(), ActorSystemError> {
        tokio::select! {
            _ = self.await_shutdown() => Ok(()),
            _ = tokio::time::sleep(timeout) => Err(ActorSystemError::ShutdownTimeout),
        }
    }
}

impl<A> ActorContext<A>
where
    A: Actor,
{
    /// access the current behavior of the [Actor] instance
    pub fn behavior(&self) -> &A::Behavior {
        &self.behavior
    }

    /// change the behavior of the [Actor] instance starting on the next message
    pub fn becomes(&mut self, new_behavior: A::Behavior) {
        self.becomes = Some(new_behavior);
    }

    /// create a new child actor at the specified path
    pub async fn spawn<C: Actor>(&self, name: &str, actor: C) -> Result<ActorRef<C>, ActorError> {
        let path = self.path.make_child(name);
        self.system.create_actor_path_impl(path, actor, self.kill.subscribe()).await
    }

    /// get a child if it exists or spawn a new child if not
    pub async fn child_or_spawn<C, F>(&self, name: &str, actor_fn: F) -> Result<ActorRef<C>, ActorError>
    where
        C: Actor,
        F: FnOnce() -> C,
    {
        let path = self.path.make_child(name);
        self.system.get_or_create_actor_path(&path, actor_fn).await
    }

    /// get a child actor
    pub async fn child<C: Actor>(&self, name: &str) -> Option<ActorRef<C>> {
        let path = self.path.make_child(name);
        self.system.get_actor(&path).await
    }

    /// get [ActorRef] for all child actors
    pub async fn children(&self) -> Vec<ActorPath> {
        self.system.children_of(&self.path).await
    }

    /// Signal the [Actor] to stop after processing the current message
    pub fn stop(&mut self) {
        let _ = self.kill.send(());
    }

    pub fn aref(&self) -> ActorRef<A> {
        self.aref.clone()
    }
}

impl<A: Actor> ActorContext<A> {
    pub async fn tell<M: Protocol>(&self, msg: M) -> Result<(), ActorError>
    where
        A: Receiver<M>,
    {
        self.aref.tell(msg).await
    }
}

impl Debug for ActorSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ActorSystem: {}", self.name)
    }
}

impl Default for ActorSystem {
    fn default() -> Self {
        ActorSystem::new("main")
    }
}

type ErasedActorRef = Box<dyn Any + Send + Sync + 'static>;
type ActorRefMap = HashMap<ActorPath, ErasedActorRef>;

#[cfg(test)]
mod tests {
    use crate::actor::{Actor, PoisonPill};
    use crate::path::ActorPath;
    use crate::system::{ActorContext, ActorSystem};
    use crate::ActorError;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct EmptyActor;
    impl Actor for EmptyActor {
        type Behavior = ();
    }

    #[tokio::test]
    async fn get_actor_by_path() {
        let sys = ActorSystem::default();
        sys.create_actor("test", EmptyActor).await.unwrap();
        let aref = sys.get_actor::<EmptyActor>(&ActorPath::new("test")).await.unwrap();
        assert_eq!("/test", aref.path().to_string());
    }

    #[derive(Default)]
    struct DestroyCountingActor {
        destroyed: Arc<AtomicUsize>,
    }

    impl DestroyCountingActor {
        fn new(destroyed: Arc<AtomicUsize>) -> Self {
            Self { destroyed }
        }
    }

    #[async_trait]
    impl Actor for DestroyCountingActor {
        type Behavior = ();

        async fn post_stop(&mut self, _ctx: &mut ActorContext<Self>) {
            self.destroyed.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn destroy_actor() -> Result<(), ActorError> {
        let same_name = "test-actor";
        let count = Arc::new(AtomicUsize::new(0));
        let sys = ActorSystem::default();

        sys.create_actor(same_name, DestroyCountingActor::new(count.clone())).await?.ask(PoisonPill).await?;
        sys.create_actor(same_name, DestroyCountingActor::new(count.clone())).await?.ask(PoisonPill).await?;
        sys.create_actor(same_name, DestroyCountingActor::new(count.clone())).await?.ask(PoisonPill).await?;

        assert_eq!(3, count.load(Ordering::Relaxed));

        Ok(())
    }
}
