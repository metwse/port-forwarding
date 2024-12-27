macro_rules! error_impl_from {
    ($( $ident:ident ),*) => {
        $(
            paste::paste! {
                impl From<[<$ident Error>]> for Error {
                    fn from(error: [<$ident Error>]) -> Self {
                        Self::$ident(error)
                    }
                }
            }
        )*
    };
}
