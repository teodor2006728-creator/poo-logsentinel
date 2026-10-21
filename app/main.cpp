#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

class LogEntry {
private:
    int timestamp_;
    std::string ip_;
    bool failed_;

    void setTimestamp(const std::string& month, int day, int hour, int minute, int second) {
        if (day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
            timestamp_ = -1;
            return;
        }

        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
        };

        timestamp_ = -1;
        for (int i = 0; i < 12; i++) {
            if (month == months[i]) {
                int days = cumulativeDays[i] + day - 1;
                timestamp_ = days * 86400 + hour * 3600 + minute * 60 + second;
                return;
            }
        }
    }

    std::string formatTime() const {
        if (timestamp_ < 0) {
            return "?";
        }

        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
        };

        int days = timestamp_ / 86400;
        int remainder = timestamp_ % 86400;

        int month = 11;
        while (month > 0 && cumulativeDays[month] > days) {
            month--;
        }

        int day = (days - cumulativeDays[month]) + 1;
        int hour = remainder / 3600;
        int minute = (remainder % 3600) / 60;
        int second = remainder % 60;

        std::string dayStr = (day < 10 ? "0" : "") + std::to_string(day);
        std::string hourStr = (hour < 10 ? "0" : "") + std::to_string(hour);
        std::string minStr = (minute < 10 ? "0" : "") + std::to_string(minute);
        std::string secStr = (second < 10 ? "0" : "") + std::to_string(second);

        return months[month] + " " + dayStr + " " + hourStr + ":" + minStr + ":" + secStr;
    }

public:
    LogEntry(const std::string& month, int day, int hour, int minute, int second, const std::string& ip, bool failed)
        : timestamp_(-1), ip_(ip), failed_(failed) {
        setTimestamp(month, day, hour, minute, second);
    }

    bool isValid() const {
        return timestamp_ >= 0;
    }

    bool hasSameIp(const LogEntry& other) const {
        return ip_ == other.ip_;
    }

    bool isBefore(const LogEntry& other) const {
        return timestamp_ < other.timestamp_;
    }

    int secondsSince(const LogEntry& start) const {
        return timestamp_ - start.timestamp_;
    }

    bool hasWindowExpired(const LogEntry& start, int windowSeconds) const {
        return (timestamp_ - start.timestamp_) > windowSeconds;
    }

    void updateCounters(int& totalAttempts, int& failedAttempts) const {
        totalAttempts++;
        if (failed_) {
            failedAttempts++;
        }
    }

    void printAlertFormat(std::ostream& os, const std::string& message) const {
        os << "[ALERT] " << ip_ << " - " << message << " (at " << formatTime() << ")";
    }

    friend std::ostream& operator<<(std::ostream& os, const LogEntry& entry) {
        os << "[" << entry.formatTime() << "] " << entry.ip_ << " " << (entry.failed_ ? "FAILED" : "SUCCESS");
        return os;
    }
};

class Alert {
private:
    std::string message_;
    LogEntry trigger_;

public:
    Alert(const std::string& message, const LogEntry& trigger)
        : message_(message), trigger_(trigger) {}

    Alert(const Alert& other)
        : message_(other.message_), trigger_(other.trigger_) {}

    Alert& operator=(const Alert& other) {
        if (this != &other) {
            message_ = other.message_;
            trigger_ = other.trigger_;
        }
        return *this;
    }

    ~Alert() {
        if (!message_.empty()) {
            message_.clear();
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const Alert& alert) {
        alert.trigger_.printAlertFormat(os, alert.message_);
        return os;
    }
};

class IpTracker {
private:
    LogEntry firstAttempt_;
    int failedAttempts_;
    int totalAttempts_;

public:
    explicit IpTracker(const LogEntry& firstAttempt)
        : firstAttempt_(firstAttempt), failedAttempts_(0), totalAttempts_(0) {
        firstAttempt.updateCounters(totalAttempts_, failedAttempts_);
    }

    bool tracksSameIp(const LogEntry& entry) const {
        return firstAttempt_.hasSameIp(entry);
    }

    void recordAttempt(const LogEntry& entry, int windowSeconds) {
        if (entry.hasWindowExpired(firstAttempt_, windowSeconds)) {
            firstAttempt_ = entry;
            totalAttempts_ = 0;
            failedAttempts_ = 0;
        }
        entry.updateCounters(totalAttempts_, failedAttempts_);
    }

    bool isAttack(int threshold, double minRatio) const {
        double currentRatio = (1.0 * failedAttempts_) / totalAttempts_;
        return failedAttempts_ >= threshold && currentRatio >= minRatio;
    }

    Alert createAlert(const LogEntry& lastAttempt) const {
        int duration = lastAttempt.secondsSince(firstAttempt_);
        std::ostringstream msg;
        msg << failedAttempts_ << " failures out of " << totalAttempts_ << " attempts in " << duration << "s";
        return Alert(msg.str(), lastAttempt);
    }

    friend std::ostream& operator<<(std::ostream& os, const IpTracker& tracker) {
        os << tracker.firstAttempt_ << " -> " << tracker.failedAttempts_ << "/" << tracker.totalAttempts_ << " failures";
        return os;
    }
};

class LogSource {
private:
    std::string filePath_;
    std::vector<LogEntry> entries_;

    void sortChronologically() {
        for (std::size_t i = 0; i < entries_.size(); i++) {
            for (std::size_t j = i + 1; j < entries_.size(); j++) {
                if (entries_[j].isBefore(entries_[i])) {
                    LogEntry temp = entries_[i];
                    entries_[i] = entries_[j];
                    entries_[j] = temp;
                }
            }
        }
    }

public:
    explicit LogSource(const std::string& filePath) : filePath_(filePath) {}

    bool load() {
        std::ifstream file(filePath_);
        if (!file.is_open()) {
            return false;
        }
        entries_.clear();

        std::string month;
        std::string ip;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        bool failed = false;

        while (file >> month >> day >> hour >> minute >> second >> ip >> failed) {
            LogEntry entry(month, day, hour, minute, second, ip, failed);
            if (entry.isValid()) {
                entries_.push_back(entry);
            }
        }

        sortChronologically();
        return true;
    }

    std::size_t getEntryCount() const {
        return entries_.size();
    }

    const LogEntry& getEntryAt(std::size_t index) const {
        return entries_[index];
    }

    friend std::ostream& operator<<(std::ostream& os, const LogSource& source) {
        os << source.filePath_ << ": " << source.entries_.size() << " authentication entries";
        return os;
    }
};

class Analyzer {
private:
    LogSource source_;
    int threshold_;
    int windowSeconds_;
    double minRatio_;
    std::vector<IpTracker> trackers_;
    std::vector<Alert> alerts_;

    int findTrackerIndex(const LogEntry& entry) const {
        for (std::size_t i = 0; i < trackers_.size(); i++) {
            if (trackers_[i].tracksSameIp(entry)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

public:
    Analyzer(const LogSource& source, int threshold = 5, int windowSeconds = 60, double minRatio = 0.8)
        : source_(source), threshold_(threshold), windowSeconds_(windowSeconds), minRatio_(minRatio) {}

    int detectAttacks() {
        trackers_.clear();
        alerts_.clear();

        for (std::size_t i = 0; i < source_.getEntryCount(); i++) {
            const LogEntry& entry = source_.getEntryAt(i);
            int index = findTrackerIndex(entry);

            if (index < 0) {
                trackers_.push_back(IpTracker(entry));
                index = static_cast<int>(trackers_.size()) - 1;
            } else {
                trackers_[static_cast<std::size_t>(index)].recordAttempt(entry, windowSeconds_);
            }

            std::size_t currentIdx = static_cast<std::size_t>(index);
            if (trackers_[currentIdx].isAttack(threshold_, minRatio_)) {
                alerts_.push_back(trackers_[currentIdx].createAlert(entry));
                trackers_.erase(trackers_.begin() + index);
            }
        }
        return static_cast<int>(alerts_.size());
    }

    void printAlerts(std::ostream& os) const {
        for (std::size_t i = 0; i < alerts_.size(); i++) {
            os << alerts_[i] << "\n";
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const Analyzer& analyzer) {
        analyzer.printAlerts(os);
        return os;
    }
};

int main(int argc, char* argv[]) {
    std::string filePath = "clean_auth.log.txt";
    if (argc > 1) {
        filePath = argv[1];
    }

    LogSource source(filePath);
    if (!source.load()) {
        std::cout << "Failed to open file: " << filePath << "\n";
        return 1;
    }

    std::cout << "=== Log Source Summary ===\n";
    std::cout << source << "\n\n";

    Analyzer analyzer(source, 5, 60, 0.8);
    int totalAlerts = analyzer.detectAttacks();

    std::cout << "=== Detected Brute-Force Alerts (" << totalAlerts << ") ===\n";
    std::cout << analyzer << "\n";

    if (source.getEntryCount() >= 2) {
        const LogEntry& firstEntry = source.getEntryAt(0);
        const LogEntry& secondEntry = source.getEntryAt(1);

        IpTracker sampleTracker(firstEntry);
        Alert originalAlert("5 failures out of 5 attempts in 10s", firstEntry);
        Alert copiedAlert(originalAlert);
        Alert assignedAlert("6 failures out of 6 attempts in 15s", secondEntry);
        originalAlert = assignedAlert;

        std::cout << "=== Component Verification ===\n";
        std::cout << "Entry:   " << firstEntry << "\n";
        std::cout << "Tracker: " << sampleTracker << "\n";
        std::cout << "Copied:  " << copiedAlert << "\n";
        std::cout << "Updated: " << originalAlert << "\n";
    }

    return 0;
}
