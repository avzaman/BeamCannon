#include "logger.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>

Logger::Logger(const std::string& path) : path_(path) {
    file_.open(path, std::ios::app);
    if (!file_.is_open())
        throw std::runtime_error("Cannot open log file: " + path);
}

Logger::~Logger() {
    if (file_.is_open())
        file_.close();
}

std::string Logger::timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

void Logger::log(const std::string& level, const std::string& msg) {
    std::lock_guard<std::mutex> lock(mtx_);
    file_ << timestamp() << " [" << level << "] " << msg << "\n";
    file_.flush();
}

void Logger::log_inject(const std::string& victim_mac,
                        double compute_ms,
                        bool success,
                        int seq) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3)
       << "victim=" << victim_mac
       << " compute_ms=" << compute_ms
       << " result=" << (success ? "ok" : "fail")
       << " seq=" << seq;
    log("INJECT", ss.str());
}

void Logger::log_summary(int total,
                          int success,
                          int failed,
                          double avg_compute_ms,
                          double sounding_interval_ms,
                          long uptime_s) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3)
       << "total=" << total
       << " success=" << success
       << " failed=" << failed
       << " avg_compute_ms=" << avg_compute_ms
       << " sounding_interval_ms=" << sounding_interval_ms
       << " uptime=" << uptime_s << "s";
    log("SUMMARY", ss.str());
}
