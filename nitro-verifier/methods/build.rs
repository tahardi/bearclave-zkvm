use std::collections::HashMap;

use risc0_build::{
    DockerOptionsBuilder, GuestOptionsBuilder, embed_methods, embed_methods_with_options,
};

fn main() {
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    if std::env::var_os("RISC0_USE_DOCKER").is_none() {
        embed_methods();
        return;
    }
    let docker = DockerOptionsBuilder::default()
        .root_dir("..")
        .docker_container_tag("r0.1.91.1")
        .build()
        .expect("building docker options");
    let guest = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .expect("building guest options");
    embed_methods_with_options(HashMap::from([("verify-nitro", guest)]));
}
