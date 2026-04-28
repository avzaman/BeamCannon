#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <ctime>

class Logger {
public:
    explicit Logger(const std::string& path);
    ~Logger();

    void log(const std::string& level, const std::string& msg);
    void log_inject(const std::string& victim_mac,
                    double compute_ms,
                    bool success,
                    int seq);
    void log_summary(int total,
                     int success,
                     int failed,
                     double avg_compute_ms,
                     double sounding_interval_ms,
                     long uptime_s);

    // Convenience wrappers
    void info(const std::string& msg)  { log("INFO",    msg); }
    void warn(const std::string& msg)  { log("WARN",    msg); }
    void error(const std::string& msg) { log("ERROR",   msg); }
    void start(const std::string& msg) { log("START",   msg); }
    void mode(const std::string& msg)  { log("MODE",    msg); }

    const std::string& path() const { return path_; }

private:
    std::string timestamp();
    std::string path_;
    std::ofstream file_;
    std::mutex mtx_;
};
