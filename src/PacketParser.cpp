#include "PacketParser.h"

uint32_t ip_string_to_uint32(const std::string& ip_str) {
    uint32_t result = 0;
    std::istringstream iss(ip_str);
    std::string octet_str;
    int shift = 24;

    while (std::getline(iss, octet_str, '.')) {
        int octet = std::stoi(octet_str);
        if (octet < 0 || octet > 255) {
            throw std::runtime_error("Invalid IP address: " + ip_str);
        }
        result |= static_cast<uint32_t>(octet) << shift;
        shift -= 8;
    }

    return result;
}

std::string uint32_to_ip_string(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.' << (ip & 0xFF);
    return oss.str();
}

size_t estimate_packet_count(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        return 100000;
    }

    std::streamsize file_size = file.tellg();
    file.close();

    constexpr size_t PACKETS_PER_MB = 13000;
    size_t file_size_mb = static_cast<size_t>(file_size / (1024 * 1024));
    size_t estimated_packets = file_size_mb * PACKETS_PER_MB;

    return estimated_packets > 0 ? estimated_packets : 10000;
}

// Pcap File Struct
namespace {

constexpr uint32_t MAGIC_MICROSECONDS_LE = 0xa1b2c3d4;
constexpr uint32_t MAGIC_MICROSECONDS_BE = 0xd4c3b2a1;
constexpr uint32_t MAGIC_NANOSECONDS_LE = 0xa1b23c4d;
constexpr uint32_t MAGIC_NANOSECONDS_BE = 0x4d3cb2a1;

#pragma pack(push, 1)
struct PcapFileHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

}  // namespace

PcapReader::PcapReader(const std::string& filename)
    : filename_(filename),
      is_big_endian_(false),
      has_nano_precision_(false),
      link_type_(pcpp::LINKTYPE_ETHERNET) {}

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open() {
    file_.open(filename_, std::ios::binary);
    if (!file_) {
        return false;
    }

    PcapFileHeader header;
    file_.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!file_) {
        return false;
    }

    switch (header.magic_number) {
        case MAGIC_MICROSECONDS_LE:
            is_big_endian_ = false;
            has_nano_precision_ = false;
            break;
        case MAGIC_MICROSECONDS_BE:
            is_big_endian_ = true;
            has_nano_precision_ = false;
            break;
        case MAGIC_NANOSECONDS_LE:
            is_big_endian_ = false;
            has_nano_precision_ = true;
            break;
        case MAGIC_NANOSECONDS_BE:
            is_big_endian_ = true;
            has_nano_precision_ = true;
            break;
        default:
            return false;
    }

    if (is_big_endian_) {
        header.network = swap_bytes32(header.network);
    }

    if (pcpp::RawPacket::isLinkTypeValid(static_cast<int>(header.network))) {
        link_type_ = static_cast<pcpp::LinkLayerType>(header.network);
    }

    return true;
}

bool PcapReader::get_next_packet(pcpp::RawPacket& raw_packet) {
    raw_packet.clear();

    while (true) {
        PcapPacketHeader pkt_header;
        file_.read(reinterpret_cast<char*>(&pkt_header), sizeof(pkt_header));
        if (!file_ || file_.gcount() == 0) {
            return false;
        }
        if (file_.gcount() != sizeof(pkt_header)) {
            throw std::runtime_error("Incomplete packet header");
        }

        if (is_big_endian_) {
            pkt_header.ts_sec = swap_bytes32(pkt_header.ts_sec);
            pkt_header.ts_usec = swap_bytes32(pkt_header.ts_usec);
            pkt_header.incl_len = swap_bytes32(pkt_header.incl_len);
            pkt_header.orig_len = swap_bytes32(pkt_header.orig_len);
        }

        // 跳过无效包
        if (pkt_header.incl_len == 0 ||
            pkt_header.incl_len > PCPP_MAX_PACKET_SIZE) {
            file_.seekg(pkt_header.incl_len, std::ios::cur);
            continue;
        }

        std::unique_ptr<uint8_t[]> packet_data(
            new uint8_t[pkt_header.incl_len]);
        file_.read(reinterpret_cast<char*>(packet_data.get()),
                   pkt_header.incl_len);
        if (!file_ ||
            static_cast<uint32_t>(file_.gcount()) != pkt_header.incl_len) {
            throw std::runtime_error("Incomplete packet data");
        }

        bool success;
        if (has_nano_precision_) {
            timespec ts;
            ts.tv_sec = static_cast<time_t>(pkt_header.ts_sec);
            ts.tv_nsec = static_cast<long>(pkt_header.ts_usec);
            success = raw_packet.setRawData(
                packet_data.get(), static_cast<int>(pkt_header.incl_len), ts,
                link_type_, static_cast<int>(pkt_header.orig_len));
        } else {
            timeval tv;
            tv.tv_sec = static_cast<long>(pkt_header.ts_sec);
            tv.tv_usec = static_cast<long>(pkt_header.ts_usec);
            success = raw_packet.setRawData(
                packet_data.get(), static_cast<int>(pkt_header.incl_len), tv,
                link_type_, static_cast<int>(pkt_header.orig_len));
        }

        if (!success) {
            throw std::runtime_error("Failed to set raw packet data");
        }

        packet_data.release();
        return true;
    }
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
}

// OneTuple特化：只提取源IP
template <>
OneTuple PacketParser<OneTuple>::extract_flow(const pcpp::Packet& packet) {
    auto* ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4_layer) {
        return OneTuple();
    }
    return OneTuple(ipv4_layer->getSrcIPv4Address().toInt());
}

// TwoTuple特化：提取源IP和目的IP
template <>
TwoTuple PacketParser<TwoTuple>::extract_flow(const pcpp::Packet& packet) {
    auto* ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4_layer) {
        return TwoTuple();
    }
    return TwoTuple(ipv4_layer->getSrcIPv4Address().toInt(),
                    ipv4_layer->getDstIPv4Address().toInt());
}

// FiveTuple特化：提取源IP、目的IP、源端口、目的端口、协议
template <>
FiveTuple PacketParser<FiveTuple>::extract_flow(const pcpp::Packet& packet) {
    auto* ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    auto* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    auto* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();

    if (!ipv4_layer) {
        return FiveTuple();
    }

    uint8_t protocol = ipv4_layer->getProtocol();
    uint16_t src_port = 0, dst_port = 0;

    if (protocol == pcpp::PACKETPP_IPPROTO_TCP && tcp_layer) {
        src_port = tcp_layer->getSrcPort();
        dst_port = tcp_layer->getDstPort();
    } else if (protocol == pcpp::PACKETPP_IPPROTO_UDP && udp_layer) {
        src_port = udp_layer->getSrcPort();
        dst_port = udp_layer->getDstPort();
    }

    return FiveTuple(ipv4_layer->getSrcIPv4Address().toInt(),
                     ipv4_layer->getDstIPv4Address().toInt(), src_port,
                     dst_port, protocol);
}

template <typename FlowKeyType, typename SFINAE>
typename PacketParser<FlowKeyType, SFINAE>::PacketVector
PacketParser<FlowKeyType, SFINAE>::parse_pcap(
    const std::string& file_path) const {
    PacketVector packets;

    PcapReader reader(file_path);
    if (!reader.open()) {
        throw std::runtime_error("Failed to open pcap file: " + file_path);
    }

    packets.reserve(estimate_packet_count(file_path));

    pcpp::RawPacket raw_packet;
    while (reader.get_next_packet(raw_packet)) {
        pcpp::Packet parsed_packet(&raw_packet, pcpp::OsiModelNetworkLayer);

        // 提取FlowKey
        FlowKeyType flow = extract_flow(parsed_packet);

        // 检查是否为有效流
        if (flow == FlowKeyType()) {
            continue;
        }

        PacketRecordType record;
        record.flow = flow;

        const timespec& ts = raw_packet.getPacketTimeStamp();
        record.timestamp = std::chrono::seconds{ts.tv_sec} +
                           std::chrono::nanoseconds{ts.tv_nsec};

        packets.push_back(record);
    }

    reader.close();

    // 按时间戳排序
    std::sort(packets.begin(), packets.end(),
              [](const PacketRecordType& a, const PacketRecordType& b) {
                  return a.timestamp < b.timestamp;
              });

    return packets;
}

template <typename FlowKeyType, typename SFINAE>
std::vector<typename PacketParser<FlowKeyType, SFINAE>::PacketVector>
PacketParser<FlowKeyType, SFINAE>::parse_pcap_with_epochs(
    const std::string& file_path, std::chrono::nanoseconds epoch) const {

    PacketVector packets = parse_pcap(file_path);

    // epoch 为 0 ，不切分
    if (epoch == std::chrono::nanoseconds{0}) {
        std::vector<PacketVector> result;
        result.push_back(packets);
        return result;
    }

    // 按 epoch 切分
    std::vector<PacketVector> result;
    if (packets.empty()) {
        return result;
    }

    auto start_time = packets.front().timestamp;
    result.emplace_back();
    auto current_epoch_start = start_time;

    // 遍历所有数据包，按时间窗口分组
    for (const auto& packet : packets) {
        auto offset = packet.timestamp - current_epoch_start;

        // 新 epoch
        while (offset >= epoch) {
            current_epoch_start += epoch;
            result.emplace_back();
            offset = packet.timestamp - current_epoch_start;
        }

        result.back().push_back(packet);
    }

    // 移除空的epoch窗口
    result.erase(
        std::remove_if(result.begin(), result.end(),
                      [](const PacketVector& pv) { return pv.empty(); }),
        result.end());

    return result;
}

// 显式实例化
template class PacketParser<OneTuple>;
template class PacketParser<TwoTuple>;
template class PacketParser<FiveTuple>;
