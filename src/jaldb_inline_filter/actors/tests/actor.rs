/***
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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
use jalop_actors::actor::{Actor, PoisonPill, Protocol, Receiver};
use jalop_actors::path::ActorPath;
use jalop_actors::system::{ActorContext, ActorSystem};
use jalop_actors::ActorError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

struct TestActor;

#[async_trait]
impl Actor for TestActor {
    type Behavior = ();

    async fn post_stop(&mut self, _ctx: &mut ActorContext<Self::Behavior>) {
        println!("stopping test actor")
    }
}

#[derive(Clone)]
enum TestMsg {
    Foo,
    Bar,
}

impl Protocol for TestMsg {
    type Response = ();
}

#[async_trait]
impl Receiver<TestMsg> for TestActor {
    async fn receive(&mut self, msg: TestMsg, ctx: &mut ActorContext<Self::Behavior>) {
        match msg {
            TestMsg::Foo => {
                println!("received foo");
                ctx.system.get_actor::<Self>(&ctx.path).await.unwrap().tell(TestMsg::Bar).await;
            }
            TestMsg::Bar => {
                println!("received bar");
                ctx.stop();
            }
        }
    }
}

#[tokio::test]
async fn send_to_self() {
    let sys = ActorSystem::default();
    let r = sys.create_actor("foo", TestActor).await.unwrap();
    r.tell(TestMsg::Foo).await;
    sleep(Duration::from_secs(1)).await;
}

struct SpawningActor(usize, Arc<Mutex<Vec<usize>>>);

#[async_trait]
impl Actor for SpawningActor {
    type Behavior = ();

    async fn pre_start(&mut self, ctx: &mut ActorContext<Self::Behavior>) -> Result<(), ActorError> {
        if self.0 > 0 {
            let next = self.0 - 1;
            println!("{} spawning actor {}", ctx.path, next);
            ctx.spawn(&format!("{next}"), SpawningActor(next, self.1.clone())).await;
        }
        Ok(())
    }

    async fn post_stop(&mut self, _ctx: &mut ActorContext<Self::Behavior>) {
        let mut log = self.1.lock().await;
        log.push(self.0);
        println!("stopping spawing actor {}", self.0);
    }
}

#[tokio::test]
async fn cascade_shutdown() {
    let sys = ActorSystem::default();
    let log: Arc<Mutex<Vec<usize>>> = Default::default();
    let top = sys.create_actor("foo", SpawningActor(5, log.clone())).await.unwrap();
    sleep(Duration::from_secs(1)).await;
    top.ask(PoisonPill).await;
    let log = log.lock().await.to_vec();
    assert_eq!(log, vec![5, 4, 3, 2, 1, 0]);
}

#[tokio::test]
async fn partial_cascade_shutdown() {
    let sys = ActorSystem::default();
    let log: Arc<Mutex<Vec<usize>>> = Default::default();
    let top = sys.create_actor("top", SpawningActor(5, log.clone())).await.unwrap();
    sleep(Duration::from_secs(1)).await;
    let three = sys.get_actor::<SpawningActor>(&ActorPath::from("top/4/3")).await.unwrap();
    three.ask(PoisonPill).await;
    let log = log.lock().await.to_vec();
    assert_eq!(log, vec![3, 2, 1, 0]);
}

#[tokio::test]
async fn system_shutdown() {
    let sys = ActorSystem::default();
    let log: Arc<Mutex<Vec<usize>>> = Default::default();
    let top = sys.create_actor("5", SpawningActor(5, log.clone())).await.unwrap();
    sleep(Duration::from_secs(1)).await;
    sys.shutdown().await;
    sleep(Duration::from_secs(1)).await;
    let log = log.lock().await.to_vec();
    assert_eq!(log, vec![5, 4, 3, 2, 1, 0]);
}
