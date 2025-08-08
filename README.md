# RustStarter

[![CI](https://github.com/shandysiswandi/ruststarter/actions/workflows/ci.yaml/badge.svg)](https://github.com/shandysiswandi/ruststarter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A modern, modular, and production-ready authentication and authorization server built in Rust. This project serves as a robust foundation for building secure and scalable web services, following Clean Architecture principles for a clear separation of concerns.

---

## ✨ Features

* **Modern Tech Stack**: Built with **Axum**, **Tokio**, and **SQLx** for high-performance, asynchronous services.
* **Clean Architecture**: A clear separation between the web layer, business logic, and data access, making the codebase highly maintainable and testable.
* **Secure by Design**: Implements secure password handling with **Argon2id** and is designed for JWT-based authentication.
* **Production Ready**: Features structured logging, centralized error handling, and dynamic configuration with auto-reloading.
* **Modular Structure**: Organized by features (`auth`, `user`, etc.), allowing for easy scaling and team collaboration.
* **Database Migrations**: Uses **Goose** for reliable, SQL-based database schema management.

---

## 🏗️ Project Structure

The project follows a "library with a binary" pattern and a feature-based modular architecture to ensure a clean separation of concerns.

```bash
.
├── config/
│   └── config.yaml      # Application configuration
├── db/migrations/
│   └── ...              # Goose database migrations
└── src/
    ├── main.rs          # Thin binary entrypoint
    ├── lib.rs           # Main library crate root
    ├── app/             # Shared application core (state, error, router)
    └── auth/            # "Auth" feature module
        ├── domain/      # Core business entities
        ├── usecase/     # Business logic services
        ├── inbound/     # Web layer (handlers, DTOs)
        └── outbound/    # Database layer (repositories)
```

---

## 🚀 Getting Started

Follow these instructions to get the project up and running on your local machine.

### Prerequisites

* **Rust Toolchain**: Install via [rustup](https://rustup.rs/) (latest stable version).
* **PostgreSQL**: A running instance of PostgreSQL. [Docker](https://www.docker.com/) is recommended.
* **Goose**: The database migration tool. Install with `go install github.com/pressly/goose/v3/cmd/goose@latest`.

### 1. Clone the Repository

```bash
git clone https://github.com/shandysiswandi/ruststarter.git

cd ruststarter
```

### 2. Set Up the Database
If using Docker, you can start a PostgreSQL container with:

```bash
docker run --name rust -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres
```

### 3. Configure the Application
Copy the example configuration file and update it with your database URL.

```bash
cp config/config.example.yaml config/config.yaml
```

Open config/config.yaml and ensure the database.url matches your setup.

### 4. Run Database Migrations
Navigate to the migrations directory and run Goose to set up the schema.

```bash
cd db/migrations

goose postgres "postgres://postgres:password@localhost:5432/rust" up
```

### 5. Run the Application
Return to the project root and run the server.

```bash
cd ../..

cargo run
```

The server should now be running and listening on the address specified in your config.yaml (e.g., http://0.0.0.0:8000).

## 🧪 Testing

To run the full test suite, use the standard cargo command:

```bash
cargo test
```

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute, please feel free to fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.