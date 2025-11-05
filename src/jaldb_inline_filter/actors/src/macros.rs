/// Used by an [Actor] to tell a [Message] to itself
#[macro_export]
macro_rules! tell_self {
    ($ctx:expr, $msg:expr) => {
        ($ctx)
            .system
            .get_actor::<Self>(&($ctx).path)
            .await
            .ok_or(ActorError::ActorStopped)?
            .tell($msg)
            .await?
    };
}
