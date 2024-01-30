fn main() {
    // Build the capnp-rust bindings
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/messages.capnp")
        .run().expect("schema compiler command");
}