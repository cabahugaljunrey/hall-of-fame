#include "crow.h"
#include <sqlite3.h>
#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <cstdlib>

// Helper to hash password with a salt using SHA-256
std::string hash_password(const std::string& password, const std::string& salt) {
    std::string salted = password + salt;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    EVP_DigestUpdate(context, salted.c_str(), salted.length());
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    EVP_MD_CTX_free(context);

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Add CORS headers to all responses
void add_cors(crow::response& res) {
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

void init_db(sqlite3* db) {
    const char* sql = "CREATE TABLE IF NOT EXISTS users ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "username TEXT UNIQUE NOT NULL, "
                      "password_hash TEXT NOT NULL, "
                      "salt TEXT NOT NULL);";
    char* err_msg = nullptr;
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        std::cerr << "DB Init Error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
}

int main() {
    crow::SimpleApp app;
    sqlite3* db;
    if (sqlite3_open("app_data.db", &db)) {
        std::cerr << "Failed to open database" << std::endl;
        return 1;
    }
    init_db(db);

    // OPTIONS preflight handlers for CORS
    CROW_ROUTE(app, "/api/register").methods(crow::HTTPMethod::Options)([](const crow::request&){
        crow::response res(204);
        add_cors(res);
        return res;
    });

    CROW_ROUTE(app, "/api/login").methods(crow::HTTPMethod::Options)([](const crow::request&){
        crow::response res(204);
        add_cors(res);
        return res;
    });

    // Register Endpoint
    CROW_ROUTE(app, "/api/register").methods(crow::HTTPMethod::Post)([&db](const crow::request& req) {
        crow::response res;
        add_cors(res);

        auto body = crow::json::load(req.body);
        if (!body || !body.has("username") || !body.has("password")) {
            res.code = 400;
            res.body = "{\"error\":\"Invalid payload\"}";
            return res;
        }

        std::string username = body["username"].s();
        std::string password = body["password"].s();
        std::string salt = "random_salt_123";
        std::string hashed_pass = hash_password(password, salt);

        std::string query = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?);";
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashed_pass.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            res.code = 409;
            res.body = "{\"error\":\"Username already exists\"}";
            return res;
        }
        sqlite3_finalize(stmt);

        res.code = 201;
        res.body = "{\"message\":\"Account created successfully\"}";
        return res;
    });

    // Login Endpoint
    CROW_ROUTE(app, "/api/login").methods(crow::HTTPMethod::Post)([&db](const crow::request& req) {
        crow::response res;
        add_cors(res);

        auto body = crow::json::load(req.body);
        if (!body || !body.has("username") || !body.has("password")) {
            res.code = 400;
            res.body = "{\"error\":\"Invalid payload\"}";
            return res;
        }

        std::string username = body["username"].s();
        std::string password = body["password"].s();

        std::string query = "SELECT password_hash, salt FROM users WHERE username = ?;";
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string stored_salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            sqlite3_finalize(stmt);

            if (hash_password(password, stored_salt) == stored_hash) {
                res.code = 200;
                res.body = "{\"message\":\"Login successful\", \"token\":\"user_auth_token_xyz\"}";
                return res;
            }
        } else {
            sqlite3_finalize(stmt);
        }

        res.code = 401;
        res.body = "{\"error\":\"Invalid username or password\"}";
        return res;
    });

    // Determine port assigned by cloud environment
    int port = 18080;
    if (const char* env_p = std::getenv("PORT")) {
        port = std::atoi(env_p);
    }

    std::cout << "Starting server on port " << port << std::endl;
    app.port(port).multithreaded().run();
    sqlite3_close(db);
}
