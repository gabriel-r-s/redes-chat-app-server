#!/bin/bash

echo "\$ cargo +nightly build && ./target/debug/chat-server-2 2>./target/log.sql"
cargo +nightly build && ./target/debug/chat-server-2 2>./target/log.sql
