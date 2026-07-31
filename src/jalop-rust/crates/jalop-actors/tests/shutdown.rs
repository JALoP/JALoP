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
use jalop_actors::actor::{Actor, Protocol, Receiver};
use jalop_actors::system::{ActorContext, ActorSystem};
use std::error::Error;
use std::time::{Duration, Instant};

#[tokio::test]
async fn await_explicit_shutdown() -> Result<(), Box<dyn Error>> {
    for d in 0..=3 {
        let sys = ActorSystem::default();
        let h = tokio::spawn({
            let sys = sys.clone();
            async move {
                let t = Instant::now();
                tokio::time::sleep(Duration::from_secs(d)).await;
                sys.terminate().await;
                t
            }
        });
        sys.await_shutdown().await;
        let e = h.await?.elapsed();
        assert!(e.as_secs() >= d);
        assert!(e.as_secs() < d + 1);
    }
    Ok(())
}

struct OnReceiveImplodingActor;
impl Actor for OnReceiveImplodingActor {
    type Behavior = ();
}

struct Boom(u64);
impl Protocol for Boom {
    type Response = ();
}

#[async_trait]
impl Receiver<Boom> for OnReceiveImplodingActor {
    async fn receive(&mut self, msg: Boom, ctx: &mut ActorContext<Self>) {
        tokio::time::sleep(Duration::from_secs(msg.0)).await;
        ctx.system.terminate().await;
    }
}

#[tokio::test]
async fn await_actor_receive_induced_shutdown() -> Result<(), Box<dyn Error>> {
    for d in 0..=3 {
        let sys = ActorSystem::default();
        let a = sys.create_actor("boom", OnReceiveImplodingActor).await?;
        let t = Instant::now();
        a.tell(Boom(d)).await?;
        sys.await_shutdown().await;
        let e = t.elapsed();
        assert!(e.as_secs() >= d);
        assert!(e.as_secs() < d + 1);
    }
    Ok(())
}
