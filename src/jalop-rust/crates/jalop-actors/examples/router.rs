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
use async_trait::async_trait;
use jalop_actors::actor::{Actor, ActorRef, Protocol, Receiver};
use jalop_actors::system::{ActorContext, ActorSystem};
use jalop_actors::ActorError;
use std::collections::VecDeque;
use std::time::Duration;

// The example demonstrates distributing a workload to a set of workers without consideration for
// fairness - the fastest workers will get the most work.
//
// The example does the following
// 1. Create a "router" that is responsible for distributing "work" to a set of "workers"
// 2. The router initializes a fixed number of workers, placing them in the "workers" queue, which identifies them as available for work
// 3. The main function pushes 1000 work entries to the router (with a small delay between each).
// 4. The router receives work, checks for an available worker, sending the work to it, or caching the work if no worker is available
// 5. Workers receive work, simulate a delay for processing, and respond to the router requesting more work
// 6. The router receives the worker's work request, any cached work is sent immediately, or worker is added back into the worker queue
// 7. The Done message signals to the router that all data has been sent, the router will shut down when all data has been processed
//    and all workers are idle. When the router is stopped it will terminate the actor system, allowing main to exit
// 8. Back-pressuring the for loop producing the work could be implemented by using the .ask() function and assigning a limit to the work queue
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let system = ActorSystem::default();
    let router = system.create_actor("router", Router::with_worker_count(5)).await?;

    for i in 0..1000 {
        let _ = router.tell(Work(i)).await;
        tokio::time::sleep(Duration::from_millis(13)).await;
    }

    router.tell(Done).await?;
    system.await_shutdown().await;

    Ok(())
}

#[derive(Debug)]
struct Work(usize);
struct Request(ActorRef<Worker>);
struct Done;

impl Protocol for Work {
    type Response = ();
}
impl Protocol for Request {
    type Response = ();
}

impl Protocol for Done {
    type Response = ();
}

struct Router {
    // worker count
    count: usize,
    // available work queue
    work: VecDeque<Work>,
    // idle worker queue
    workers: VecDeque<ActorRef<Worker>>,
}

impl Router {
    fn with_worker_count(count: usize) -> Self {
        Self {
            count,
            work: Default::default(),
            workers: Default::default(),
        }
    }
}

#[async_trait]
impl Actor for Router {
    type Behavior = ();

    async fn pre_start(&mut self, ctx: &mut ActorContext<Self>) -> Result<(), ActorError> {
        for i in 0..self.count {
            let name = &format!("worker{i}");
            println!("router pre_start creating worker {name}");
            let aref = ctx.spawn(name, Worker::new(i as u64, ctx.aref())).await?;
            let _ = ctx.tell(Request(aref)).await;
        }
        Ok(())
    }
    async fn post_stop(&mut self, ctx: &mut ActorContext<Self>) {
        println!("============ Router Stopping ============");
        let _ = ctx.system.terminate().await;
    }
}

#[async_trait]
impl Receiver<Work> for Router {
    async fn receive(&mut self, msg: Work, _ctx: &mut ActorContext<Self>) {
        println!("router received work");
        match self.workers.pop_front() {
            Some(worker) => {
                println!("sending work to requester");
                let _ = worker.tell(msg).await;
            }
            None => {
                println!("enqueued work");
                self.work.push_back(msg)
            }
        };
    }
}

#[async_trait]
impl Receiver<Request> for Router {
    async fn receive(&mut self, msg: Request, _ctx: &mut ActorContext<Self>) {
        match self.work.pop_front() {
            Some(work) => {
                let _ = msg.0.tell(work).await;
            }
            None => self.workers.push_back(msg.0),
        };
        println!(
            "handled request: work: {}, available workers: {}",
            self.work.len(),
            self.workers.len()
        );
    }
}

#[async_trait]
impl Receiver<Done> for Router {
    async fn receive(&mut self, _msg: Done, ctx: &mut ActorContext<Self>) {
        if self.work.is_empty() && self.workers.len() == self.count {
            ctx.stop();
        } else {
            // try again later
            let _ = ctx.tell(Done).await;
        }
    }
}

struct Worker {
    delay: Duration,
    completed: usize,
    router: ActorRef<Router>,
}

impl Worker {
    fn new(delay: u64, router: ActorRef<Router>) -> Self {
        Self {
            delay: Duration::from_millis((delay + 1) * 33),
            completed: 0,
            router,
        }
    }
}

#[async_trait]
impl Actor for Worker {
    type Behavior = ();
}

#[async_trait]
impl Receiver<Work> for Worker {
    async fn receive(&mut self, msg: Work, ctx: &mut ActorContext<Self>) {
        // complete the work (takes some time)
        tokio::time::sleep(self.delay).await;

        let _ = self.router.tell(Request(ctx.aref())).await;
        self.completed += 1;
        println!(
            "worker {} completed work #{} - the {} job it completed",
            ctx.path, msg.0, self.completed
        );
    }
}
