// helper trait for verifier
pub trait BoolResult {
    fn ok_or_err<E>(self, err: E) -> Result<(), E>;
}

impl BoolResult for bool {
    #[inline]
    fn ok_or_err<E>(self, err: E) -> Result<(), E> {
        if self {
            Ok(())
        } else {
            Err(err)
        }
    }
}
