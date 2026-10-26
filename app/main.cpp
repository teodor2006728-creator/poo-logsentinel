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

    static bool isValidIpv4Format(const std::string& ip) {
        if (ip.empty() || ip.size() > 15) {
            return false;
        }

        int dots = 0;
        int currentOctet = 0;
        int digitsInOctet = 0;

        for (std::size_t i = 0; i < ip.size(); i++) {
            char c = ip[i];
            if (c == '.') {
                if (digitsInOctet == 0 || currentOctet > 255) {
                    return false;
                }
                dots++;
                currentOctet = 0;
                digitsInOctet = 0;
            } else if (c >= '0' && c <= '9') {
                currentOctet = currentOctet * 10 + (c - '0');
                digitsInOctet++;
                if (digitsInOctet > 3 || currentOctet > 255) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return (dots == 3 && digitsInOctet > 0 && currentOctet <= 255);
    }

    void setTimestamp(const std::string& month, int day, int hour, int minute, int second) {
        if (day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
            timestamp_ = -1;
            return;
        }

        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int daysInMonth[12] = {
            31, 28, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
        };

        timestamp_ = -1;
        for (int i = 0; i < 12; i++) {
            if (month == months[i]) {
                if (day > daysInMonth[i]) {
                    timestamp_ = -1;
                    return;
                }
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
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
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
        if (isValidIpv4Format(ip)) {
            setTimestamp(month, day, hour, minute, second);
        }
    }

    bool isValid() const {
        return timestamp_ >= 0 && !ip_.empty();
    }

    bool hasSameIp(const LogEntry& other) const {
        return ip_ == other.ip_;
    }

    bool matchesIpString(const std::string& targetIp) const {
        return ip_ == targetIp;
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

    void printAlertFormat(std::ostream& os, const std::string& category, const std::string& severity, const std::string& message) const {
        os << "[" << category << ":" << severity << "] IP " << ip_ << " - " << message << " (at " << formatTime() << ")";
    }

    friend std::ostream& operator<<(std::ostream& os, const LogEntry& entry) {
        os << "[SSH " << entry.formatTime() << "] " << entry.ip_ << " " << (entry.failed_ ? "FAILED" : "SUCCESS");
        return os;
    }
};

class FirewallEntry {
private:
    int timestamp_;
    std::string sourceIp_;
    int destPort_;
    std::string protocol_;
    bool blocked_;

    static bool isValidIpv4Format(const std::string& ip) {
        if (ip.empty() || ip.size() > 15) {
            return false;
        }

        int dots = 0;
        int currentOctet = 0;
        int digitsInOctet = 0;

        for (std::size_t i = 0; i < ip.size(); i++) {
            char c = ip[i];
            if (c == '.') {
                if (digitsInOctet == 0 || currentOctet > 255) {
                    return false;
                }
                dots++;
                currentOctet = 0;
                digitsInOctet = 0;
            } else if (c >= '0' && c <= '9') {
                currentOctet = currentOctet * 10 + (c - '0');
                digitsInOctet++;
                if (digitsInOctet > 3 || currentOctet > 255) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return (dots == 3 && digitsInOctet > 0 && currentOctet <= 255);
    }

    static bool isValidPortAndProtocol(int port, const std::string& proto) {
        bool validPort = (port >= 1 && port <= 65535);
        bool validProto = (proto == "TCP" || proto == "UDP" || proto == "ICMP");
        return validPort && validProto;
    }

    void setTimestamp(const std::string& month, int day, int hour, int minute, int second) {
        if (day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
            timestamp_ = -1;
            return;
        }

        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int daysInMonth[12] = {
            31, 28, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
        };

        timestamp_ = -1;
        for (int i = 0; i < 12; i++) {
            if (month == months[i]) {
                if (day > daysInMonth[i]) {
                    timestamp_ = -1;
                    return;
                }
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
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
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
    FirewallEntry(const std::string& month, int day, int hour, int minute, int second,
                  const std::string& sourceIp, int destPort, const std::string& protocol, bool blocked)
        : timestamp_(-1), sourceIp_(sourceIp), destPort_(destPort), protocol_(protocol), blocked_(blocked) {
        if (isValidIpv4Format(sourceIp) && isValidPortAndProtocol(destPort, protocol)) {
            setTimestamp(month, day, hour, minute, second);
        }
    }

    bool isValid() const {
        return timestamp_ >= 0 && !sourceIp_.empty();
    }

    bool hasSameSourceIp(const FirewallEntry& other) const {
        return sourceIp_ == other.sourceIp_;
    }

    bool matchesIpString(const std::string& targetIp) const {
        return sourceIp_ == targetIp;
    }

    bool matchesLogEntryIp(const LogEntry& sshEntry) const {
        return sshEntry.matchesIpString(sourceIp_);
    }

    bool isBefore(const FirewallEntry& other) const {
        return timestamp_ < other.timestamp_;
    }

    int secondsSince(const FirewallEntry& start) const {
        return timestamp_ - start.timestamp_;
    }

    bool hasWindowExpired(const FirewallEntry& start, int windowSeconds) const {
        return (timestamp_ - start.timestamp_) > windowSeconds;
    }

    bool targetsCriticalService() const {
        const int criticalPorts[7] = {21, 22, 23, 445, 1433, 3306, 3389};
        for (int i = 0; i < 7; i++) {
            if (destPort_ == criticalPorts[i]) {
                return true;
            }
        }
        return false;
    }

    void updateScanMetrics(std::vector<int>& distinctPorts, int& blockedCount, int& criticalHits) const {
        if (!blocked_) {
            return;
        }
        blockedCount++;
        if (targetsCriticalService()) {
            criticalHits++;
        }

        bool alreadyRecorded = false;
        for (std::size_t i = 0; i < distinctPorts.size(); i++) {
            if (distinctPorts[i] == destPort_) {
                alreadyRecorded = true;
                break;
            }
        }
        if (!alreadyRecorded) {
            distinctPorts.push_back(destPort_);
        }
    }

    LogEntry toTriggerEntry() const {
        if (timestamp_ < 0) {
            return LogEntry("Jan", 1, 0, 0, 0, sourceIp_, blocked_);
        }
        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
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

        return LogEntry(months[month], day, hour, minute, second, sourceIp_, blocked_);
    }

    friend std::ostream& operator<<(std::ostream& os, const FirewallEntry& fw) {
        os << "[FW  " << fw.formatTime() << "] " << (fw.blocked_ ? "BLOCK" : "ALLOW")
           << " " << fw.protocol_ << " from " << fw.sourceIp_ << " -> port " << fw.destPort_;
        return os;
    }
};

class Alert {
private:
    std::string category_;
    std::string severity_;
    std::string message_;
    LogEntry trigger_;

    static std::string computeSeverityLabel(int score) {
        if (score >= 8) {
            return "CRITICAL";
        }
        if (score >= 5) {
            return "HIGH";
        }
        return "MEDIUM";
    }

public:
    Alert(const std::string& category, const std::string& message, const LogEntry& trigger, int riskScore = 5)
        : category_(category), severity_(computeSeverityLabel(riskScore)), message_(message), trigger_(trigger) {}

    Alert(const Alert& other)
        : category_(other.category_), severity_(other.severity_), message_(other.message_), trigger_(other.trigger_) {}

    Alert& operator=(const Alert& other) {
        if (this != &other) {
            category_ = other.category_;
            severity_ = other.severity_;
            message_ = other.message_;
            trigger_ = other.trigger_;
        }
        return *this;
    }

    ~Alert() {
        if (!message_.empty()) {
            message_.clear();
        }
        if (!category_.empty()) {
            category_.clear();
        }
        if (!severity_.empty()) {
            severity_.clear();
        }
    }

    bool isHighOrCritical() const {
        return severity_ == "HIGH" || severity_ == "CRITICAL";
    }

    bool involvesSameIpAs(const Alert& other) const {
        return trigger_.hasSameIp(other.trigger_);
    }

    bool matchesIpString(const std::string& targetIp) const {
        return trigger_.matchesIpString(targetIp);
    }

    Alert promoteToCorrelatedAlert(const Alert& secondStage) const {
        std::string combinedMsg = "Multi-stage attack: Stage 1 (" + category_ + ": " + message_
                                + ") -> Stage 2 (" + secondStage.category_ + ": " + secondStage.message_ + ")";
        return Alert("SIEM-CORRELATION", combinedMsg, secondStage.trigger_, 10);
    }

    friend std::ostream& operator<<(std::ostream& os, const Alert& alert) {
        alert.trigger_.printAlertFormat(os, alert.category_, alert.severity_, alert.message_);
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
        if (totalAttempts_ <= 0) {
            return false;
        }
        double currentRatio = (1.0 * failedAttempts_) / totalAttempts_;
        return failedAttempts_ >= threshold && currentRatio >= minRatio;
    }

    Alert createAlert(const LogEntry& lastAttempt) const {
        int duration = lastAttempt.secondsSince(firstAttempt_);
        std::ostringstream msg;
        msg << failedAttempts_ << " SSH failures out of " << totalAttempts_ << " attempts in " << duration << "s";
        return Alert("SSH-BRUTEFORCE", msg.str(), lastAttempt, failedAttempts_);
    }

    friend std::ostream& operator<<(std::ostream& os, const IpTracker& tracker) {
        os << tracker.firstAttempt_ << " -> " << tracker.failedAttempts_ << "/" << tracker.totalAttempts_ << " SSH failures";
        return os;
    }
};

class PortScanTracker {
private:
    FirewallEntry firstPacket_;
    std::vector<int> distinctPorts_;
    int blockedPackets_;
    int criticalPortHits_;

public:
    explicit PortScanTracker(const FirewallEntry& firstPacket)
        : firstPacket_(firstPacket), blockedPackets_(0), criticalPortHits_(0) {
        firstPacket.updateScanMetrics(distinctPorts_, blockedPackets_, criticalPortHits_);
    }

    bool tracksSameIp(const FirewallEntry& entry) const {
        return firstPacket_.hasSameSourceIp(entry);
    }

    void recordPacket(const FirewallEntry& entry, int windowSeconds) {
        if (entry.hasWindowExpired(firstPacket_, windowSeconds)) {
            firstPacket_ = entry;
            distinctPorts_.clear();
            blockedPackets_ = 0;
            criticalPortHits_ = 0;
        }
        entry.updateScanMetrics(distinctPorts_, blockedPackets_, criticalPortHits_);
    }

    bool isPortScan(int minDistinctPorts) const {
        return static_cast<int>(distinctPorts_.size()) >= minDistinctPorts;
    }

    Alert createScanAlert(const FirewallEntry& lastPacket) const {
        int duration = lastPacket.secondsSince(firstPacket_);
        std::ostringstream msg;
        msg << distinctPorts_.size() << " distinct ports probed (" << blockedPackets_
            << " blocked packets, " << criticalPortHits_ << " critical services) in " << duration << "s";
        int riskScore = static_cast<int>(distinctPorts_.size()) + criticalPortHits_;
        return Alert("FW-PORTSCAN", msg.str(), lastPacket.toTriggerEntry(), riskScore);
    }

    friend std::ostream& operator<<(std::ostream& os, const PortScanTracker& tracker) {
        os << tracker.firstPacket_ << " -> " << tracker.distinctPorts_.size()
           << " distinct ports (" << tracker.blockedPackets_ << " blocked)";
        return os;
    }
};

class LogSource {
private:
    std::string filePath_;
    std::vector<LogEntry> entries_;
    int ignoredLines_;

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
    explicit LogSource(const std::string& filePath)
        : filePath_(filePath), ignoredLines_(0) {}

    void ingestFromStream(std::istream& in, int lineCount) {
        std::ofstream outFile(filePath_, std::ios::app);
        for (int i = 0; i < lineCount; i++) {
            std::string month;
            std::string ip;
            int day = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            bool failed = false;

            if (in >> month >> day >> hour >> minute >> second >> ip >> failed) {
                if (outFile.is_open()) {
                    outFile << month << " " << day << " " << hour << " "
                            << minute << " " << second << " " << ip << " " << failed << "\n";
                }
                LogEntry entry(month, day, hour, minute, second, ip, failed);
                if (entry.isValid()) {
                    entries_.push_back(entry);
                } else {
                    ignoredLines_++;
                }
            }
        }
        sortChronologically();
    }

    bool loadFromFile() {
        std::ifstream file(filePath_);
        if (!file.is_open()) {
            return false;
        }
        entries_.clear();
        ignoredLines_ = 0;

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
            } else {
                ignoredLines_++;
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

    int printEntriesForIp(std::ostream& os, const std::string& targetIp) const {
        int matched = 0;
        for (std::size_t i = 0; i < entries_.size(); i++) {
            if (entries_[i].matchesIpString(targetIp)) {
                os << "  " << entries_[i] << "\n";
                matched++;
            }
        }
        return matched;
    }

    friend std::ostream& operator<<(std::ostream& os, const LogSource& source) {
        os << "[SSH Source] " << source.filePath_ << ": " << source.entries_.size()
           << " valid entries (" << source.ignoredLines_ << " invalid ignored)";
        return os;
    }
};

class FirewallSource {
private:
    std::string filePath_;
    std::vector<FirewallEntry> entries_;
    int ignoredLines_;

    void sortChronologically() {
        for (std::size_t i = 0; i < entries_.size(); i++) {
            for (std::size_t j = i + 1; j < entries_.size(); j++) {
                if (entries_[j].isBefore(entries_[i])) {
                    FirewallEntry temp = entries_[i];
                    entries_[i] = entries_[j];
                    entries_[j] = temp;
                }
            }
        }
    }

public:
    explicit FirewallSource(const std::string& filePath)
        : filePath_(filePath), ignoredLines_(0) {}

    void ingestFromStream(std::istream& in, int packetCount) {
        std::ofstream outFile(filePath_, std::ios::app);
        for (int i = 0; i < packetCount; i++) {
            std::string month;
            std::string ip;
            std::string proto;
            int day = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            int port = 0;
            bool blocked = false;

            if (in >> month >> day >> hour >> minute >> second >> ip >> port >> proto >> blocked) {
                if (outFile.is_open()) {
                    outFile << month << " " << day << " " << hour << " " << minute << " "
                            << second << " " << ip << " " << port << " " << proto << " " << blocked << "\n";
                }
                FirewallEntry entry(month, day, hour, minute, second, ip, port, proto, blocked);
                if (entry.isValid()) {
                    entries_.push_back(entry);
                } else {
                    ignoredLines_++;
                }
            }
        }
        sortChronologically();
    }

    bool loadFromFile() {
        std::ifstream file(filePath_);
        if (!file.is_open()) {
            return false;
        }
        entries_.clear();
        ignoredLines_ = 0;

        std::string month;
        std::string ip;
        std::string proto;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        int port = 0;
        bool blocked = false;

        while (file >> month >> day >> hour >> minute >> second >> ip >> port >> proto >> blocked) {
            FirewallEntry entry(month, day, hour, minute, second, ip, port, proto, blocked);
            if (entry.isValid()) {
                entries_.push_back(entry);
            } else {
                ignoredLines_++;
            }
        }

        sortChronologically();
        return true;
    }

    std::size_t getEntryCount() const {
        return entries_.size();
    }

    const FirewallEntry& getEntryAt(std::size_t index) const {
        return entries_[index];
    }

    int printPacketsForIp(std::ostream& os, const std::string& targetIp) const {
        int matched = 0;
        for (std::size_t i = 0; i < entries_.size(); i++) {
            if (entries_[i].matchesIpString(targetIp)) {
                os << "  " << entries_[i]
                   << (entries_[i].targetsCriticalService() ? " [CRITICAL-PORT]" : "") << "\n";
                matched++;
            }
        }
        return matched;
    }

    friend std::ostream& operator<<(std::ostream& os, const FirewallSource& source) {
        os << "[FW  Source] " << source.filePath_ << ": " << source.entries_.size()
           << " valid packets (" << source.ignoredLines_ << " invalid ignored)";
        return os;
    }
};

class Analyzer {
private:
    LogSource sshSource_;
    FirewallSource fwSource_;
    int sshThreshold_;
    int portScanThreshold_;
    int windowSeconds_;
    double minFailureRatio_;
    std::vector<IpTracker> sshTrackers_;
    std::vector<PortScanTracker> fwTrackers_;
    std::vector<Alert> sshAlerts_;
    std::vector<Alert> fwAlerts_;
    std::vector<Alert> correlatedAlerts_;

    int findSshTrackerIndex(const LogEntry& entry) const {
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            if (sshTrackers_[i].tracksSameIp(entry)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    int findFwTrackerIndex(const FirewallEntry& entry) const {
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            if (fwTrackers_[i].tracksSameIp(entry)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

public:
    explicit Analyzer(const LogSource& sshSource, const FirewallSource& fwSource,
                      int sshThreshold = 5, int portScanThreshold = 4,
                      int windowSeconds = 60, double minFailureRatio = 0.8)
        : sshSource_(sshSource),
          fwSource_(fwSource),
          sshThreshold_(sshThreshold),
          portScanThreshold_(portScanThreshold),
          windowSeconds_(windowSeconds),
          minFailureRatio_(minFailureRatio) {}

    void syncSources(const LogSource& sshSource, const FirewallSource& fwSource) {
        sshSource_ = sshSource;
        fwSource_ = fwSource;
    }

    void updatePolicy(int sshThreshold, int portScanThreshold, int windowSeconds, double minFailureRatio) {
        if (sshThreshold > 0) {
            sshThreshold_ = sshThreshold;
        }
        if (portScanThreshold > 0) {
            portScanThreshold_ = portScanThreshold;
        }
        if (windowSeconds > 0) {
            windowSeconds_ = windowSeconds;
        }
        if (minFailureRatio > 0.0 && minFailureRatio <= 1.0) {
            minFailureRatio_ = minFailureRatio;
        }
    }

    int detectSshBruteForce() {
        sshTrackers_.clear();
        sshAlerts_.clear();

        for (std::size_t i = 0; i < sshSource_.getEntryCount(); i++) {
            const LogEntry& entry = sshSource_.getEntryAt(i);
            int index = findSshTrackerIndex(entry);

            if (index < 0) {
                sshTrackers_.push_back(IpTracker(entry));
                index = static_cast<int>(sshTrackers_.size()) - 1;
            } else {
                sshTrackers_[static_cast<std::size_t>(index)].recordAttempt(entry, windowSeconds_);
            }

            std::size_t currentIdx = static_cast<std::size_t>(index);
            if (sshTrackers_[currentIdx].isAttack(sshThreshold_, minFailureRatio_)) {
                sshAlerts_.push_back(sshTrackers_[currentIdx].createAlert(entry));
                sshTrackers_.erase(sshTrackers_.begin() + index);
            }
        }
        return static_cast<int>(sshAlerts_.size());
    }

    int detectFirewallPortScans() {
        fwTrackers_.clear();
        fwAlerts_.clear();

        for (std::size_t i = 0; i < fwSource_.getEntryCount(); i++) {
            const FirewallEntry& packet = fwSource_.getEntryAt(i);
            int index = findFwTrackerIndex(packet);

            if (index < 0) {
                fwTrackers_.push_back(PortScanTracker(packet));
                index = static_cast<int>(fwTrackers_.size()) - 1;
            } else {
                fwTrackers_[static_cast<std::size_t>(index)].recordPacket(packet, windowSeconds_);
            }

            std::size_t currentIdx = static_cast<std::size_t>(index);
            if (fwTrackers_[currentIdx].isPortScan(portScanThreshold_)) {
                fwAlerts_.push_back(fwTrackers_[currentIdx].createScanAlert(packet));
                fwTrackers_.erase(fwTrackers_.begin() + index);
            }
        }
        return static_cast<int>(fwAlerts_.size());
    }

    int correlateMultiStageAttacks() {
        correlatedAlerts_.clear();

        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            for (std::size_t j = 0; j < sshAlerts_.size(); j++) {
                if (fwAlerts_[i].involvesSameIpAs(sshAlerts_[j])) {
                    correlatedAlerts_.push_back(fwAlerts_[i].promoteToCorrelatedAlert(sshAlerts_[j]));
                }
            }
        }
        return static_cast<int>(correlatedAlerts_.size());
    }

    int runFullSiemAnalysis() {
        int sshCount = detectSshBruteForce();
        int fwCount = detectFirewallPortScans();
        int corrCount = correlateMultiStageAttacks();
        return sshCount + fwCount + corrCount;
    }

    int countHighSeverityIncidents() const {
        int count = 0;
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            if (sshAlerts_[i].isHighOrCritical()) {
                count++;
            }
        }
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            if (fwAlerts_[i].isHighOrCritical()) {
                count++;
            }
        }
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            if (correlatedAlerts_[i].isHighOrCritical()) {
                count++;
            }
        }
        return count;
    }

    void printAlertsForIp(std::ostream& os, const std::string& targetIp) const {
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            if (fwAlerts_[i].matchesIpString(targetIp)) {
                os << "  " << fwAlerts_[i] << "\n";
            }
        }
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            if (sshAlerts_[i].matchesIpString(targetIp)) {
                os << "  " << sshAlerts_[i] << "\n";
            }
        }
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            if (correlatedAlerts_[i].matchesIpString(targetIp)) {
                os << "  " << correlatedAlerts_[i] << "\n";
            }
        }
    }

    bool hasAnyAlerts() const {
        return !correlatedAlerts_.empty() || !sshAlerts_.empty() || !fwAlerts_.empty();
    }

    Alert getTopPriorityAlert() const {
        if (!correlatedAlerts_.empty()) {
            return correlatedAlerts_[0];
        }
        if (!sshAlerts_.empty()) {
            return sshAlerts_[0];
        }
        return fwAlerts_[0];
    }

    void printActiveTrackers(std::ostream& os) const {
        os << "Active SSH Trackers (" << sshTrackers_.size() << "):\n";
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            os << "  " << sshTrackers_[i] << "\n";
        }
        os << "Active Firewall Trackers (" << fwTrackers_.size() << "):\n";
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            os << "  " << fwTrackers_[i] << "\n";
        }
    }

    void printReport(std::ostream& os) const {
        os << "--- A. Firewall Port Scan Alerts (" << fwAlerts_.size() << ") ---\n";
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            os << "  " << fwAlerts_[i] << "\n";
        }

        os << "--- B. SSH Brute-Force Alerts (" << sshAlerts_.size() << ") ---\n";
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            os << "  " << sshAlerts_[i] << "\n";
        }

        os << "--- C. Cross-Log Correlated SIEM Alerts (" << correlatedAlerts_.size() << ") ---\n";
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            os << "  " << correlatedAlerts_[i] << "\n";
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const Analyzer& analyzer) {
        analyzer.printReport(os);
        return os;
    }
};

class SiemConsoleApp {
private:
    LogSource sshSource_;
    FirewallSource fwSource_;
    Analyzer analyzer_;
    std::vector<Alert> archivedAlerts_;

    void printMenuHeader() const {
        std::cout << "\n=========================================================\n";
        std::cout << "             LOGSENTINEL SIEM CONSOLE MENU               \n";
        std::cout << "             Archived Incidents: " << archivedAlerts_.size() << "\n";
        std::cout << "=========================================================\n";
        std::cout << " [1] Ingest SSH authentication logs from input\n";
        std::cout << " [2] Ingest Firewall packet logs from input\n";
        std::cout << " [3] Update SIEM detection policy thresholds\n";
        std::cout << " [4] Run full SIEM correlation scan & view report\n";
        std::cout << " [5] Investigate specific IP address activity\n";
        std::cout << " [6] Archive & escalate top priority alert\n";
        std::cout << " [0] Exit application\n";
        std::cout << "Select option: ";
    }

    void handleSshIngestion(std::istream& in) {
        int lineCount = 0;
        if (!(in >> lineCount) || lineCount <= 0) {
            return;
        }
        sshSource_.ingestFromStream(in, lineCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "\nUpdated " << sshSource_ << "\n";
    }

    void handleFirewallIngestion(std::istream& in) {
        int packetCount = 0;
        if (!(in >> packetCount) || packetCount <= 0) {
            return;
        }
        fwSource_.ingestFromStream(in, packetCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "\nUpdated " << fwSource_ << "\n";
    }

    void handlePolicyUpdate(std::istream& in) {
        int sshThresh = 5;
        int fwThresh = 4;
        int windowSec = 60;
        double ratio = 0.8;

        if (in >> sshThresh >> fwThresh >> windowSec >> ratio) {
            analyzer_.updatePolicy(sshThresh, fwThresh, windowSec, ratio);
            std::cout << "\nSIEM Policy updated: SSH Threshold=" << sshThresh
                      << ", FW Port Threshold=" << fwThresh
                      << ", Window=" << windowSec << "s"
                      << ", MinFailureRatio=" << ratio << "\n";
        }
    }

    void handleFullScan() {
        analyzer_.syncSources(sshSource_, fwSource_);
        int totalAlerts = analyzer_.runFullSiemAnalysis();
        int highSeverity = analyzer_.countHighSeverityIncidents();

        std::cout << "\n=== SIEM Scan Completed: " << totalAlerts
                  << " alerts (" << highSeverity << " HIGH/CRITICAL) ===\n";
        std::cout << analyzer_;
        analyzer_.printActiveTrackers(std::cout);
    }

    void handleIpInvestigation(std::istream& in) const {
        std::string targetIp;
        if (!(in >> targetIp)) {
            return;
        }
        std::cout << "\n=== Threat Intelligence Report for IP: " << targetIp << " ===\n";
        std::cout << "SSH Activity:\n";
        int sshHits = sshSource_.printEntriesForIp(std::cout, targetIp);
        std::cout << "Firewall Activity:\n";
        int fwHits = fwSource_.printPacketsForIp(std::cout, targetIp);

        if (sshHits > 0 && fwHits > 0 && sshSource_.getEntryCount() > 0 && fwSource_.getEntryCount() > 0) {
            const LogEntry& sampleSsh = sshSource_.getEntryAt(0);
            const FirewallEntry& sampleFw = fwSource_.getEntryAt(0);
            if (sampleFw.matchesLogEntryIp(sampleSsh)) {
                std::cout << "Cross-check confirmed: Primary SSH & FW entries share source IP.\n";
            }
        }

        std::cout << "Triggered Alerts for " << targetIp << ":\n";
        analyzer_.printAlertsForIp(std::cout, targetIp);
    }

    void handleAlertArchival() {
        if (!analyzer_.hasAnyAlerts()) {
            std::cout << "\nNo active alerts available to archive.\n";
            return;
        }

        Alert topAlert = analyzer_.getTopPriorityAlert();
        Alert snapshotCopy(topAlert);

        if (sshSource_.getEntryCount() > 0) {
            Alert escalatedAlert("SOC-ESCALATION", "Incident assigned to Tier-2 Blue Team responder",
                                 sshSource_.getEntryAt(0), 9);
            topAlert = escalatedAlert;
        }

        archivedAlerts_.push_back(snapshotCopy);
        archivedAlerts_.push_back(topAlert);

        std::cout << "\n=== Incident Archival & Escalation ===\n";
        std::cout << "Archived Snapshot:  " << snapshotCopy << "\n";
        std::cout << "Escalated Incident: " << topAlert << "\n";
    }

public:
    SiemConsoleApp(const std::string& sshFile, const std::string& fwFile)
        : sshSource_(sshFile),
          fwSource_(fwFile),
          analyzer_(sshSource_, fwSource_, 5, 4, 60, 0.8) {
        std::ofstream clearSsh(sshFile, std::ios::trunc);
        std::ofstream clearFw(fwFile, std::ios::trunc);
        sshSource_.loadFromFile();
        fwSource_.loadFromFile();
    }

    void run(std::istream& in) {
        int option = -1;
        while (true) {
            printMenuHeader();
            if (!(in >> option)) {
                std::cout << "\nInput stream closed. Exiting LogSentinel SIEM.\n";
                break;
            }

            if (option == 0) {
                std::cout << "\nShutting down LogSentinel SIEM Console.\n";
                break;
            } else if (option == 1) {
                handleSshIngestion(in);
            } else if (option == 2) {
                handleFirewallIngestion(in);
            } else if (option == 3) {
                handlePolicyUpdate(in);
            } else if (option == 4) {
                handleFullScan();
            } else if (option == 5) {
                handleIpInvestigation(in);
            } else if (option == 6) {
                handleAlertArchival();
            } else {
                std::cout << "\nUnknown command code: " << option << "\n";
            }
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const SiemConsoleApp& app) {
        os << app.sshSource_ << "\n" << app.fwSource_
           << "\nArchived Incidents: " << app.archivedAlerts_.size();
        return os;
    }
};

int main() {
    SiemConsoleApp app("clean_auth.log.txt", "clean_fw.log.txt");
    app.run(std::cin);
    std::cout << "\n=== Final SIEM Session State ===\n" << app << "\n";
    return 0;
}
