#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "FlowKey.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

// 辅助函数
uint32_t ip_string_to_uint32(const std::string& ip_str);
std::string uint32_to_ip_string(uint32_t ip);
size_t estimate_packet_count(const std::string& file_path);

// 字节序转换
inline uint16_t swap_bytes16(uint16_t val) {
    return (val >> 8) | (val << 8);
}

inline uint32_t swap_bytes32(uint32_t val) {
    return ((val & 0x000000FF) << 24) | ((val & 0x0000FF00) << 8) |
           ((val & 0x00FF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

// Pcap文件读取器
class PcapReader {
   public:
    explicit PcapReader(const std::string& filename);
    ~PcapReader();

    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    bool open();
    bool get_next_packet(pcpp::RawPacket& raw_packet);
    void close();

   private:
    std::string filename_;
    std::ifstream file_;
    bool is_big_endian_;
    bool has_nano_precision_;
    pcpp::LinkLayerType link_type_;
};

// 数据包记录模板
template <typename FlowKeyType>
struct PacketRecord {
    FlowKeyType flow;
    std::chrono::nanoseconds timestamp;
};

// PacketParser模板
template <typename FlowKeyType, typename SFINAE = RequireFlowKey<FlowKeyType>>
class PacketParser {
   public:
    using PacketRecordType = PacketRecord<FlowKeyType>;
    using PacketVector = std::vector<PacketRecordType>;

    PacketVector parse_pcap(const std::string& file_path) const;
    std::vector<PacketVector> parse_pcap_with_epochs(const std::string& file_path,
                                                    std::chrono::nanoseconds epoch = std::chrono::nanoseconds{0}) const;

   private:
    // FlowKey提取函数
    static FlowKeyType extract_flow(const pcpp::Packet& packet);
};

#endif
