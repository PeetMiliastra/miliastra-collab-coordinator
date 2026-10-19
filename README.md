# miliastra/collab coordinator

This is the default coordinator service for miliastra/collab.
If you are a standard user, you do not need this!

This service sends and receives *encrypted* metadata to facilitate communication between miliastra/collab clients. No readable data about you, your stage, your friends, your cat or your neighbour is ever processed in the service.

If you deem the default coordinator service untrustworthy, you can checkout this repo to host your own.
To change the service URL in miliastra/collab, edit `%LOCALAPPDATA%\dev.miliastra.collab\coordination.json`

## Build and run

From this project's root:

    cargo build --locked --release
    cargo run --locked --release

Set DATABASE_URL, PUBLIC_URL and optionally BIND_ADDR before running. The executable is target/release/miliastra-service (add .exe on Windows).

For Docker, copy .env.example to .env in this directory, set a strong POSTGRES_PASSWORD, then run:

    docker compose up --build -d