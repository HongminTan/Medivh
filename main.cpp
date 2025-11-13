#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "CountMin.h"
#include "CountSketch.h"
#include "ElasticSketch.h"
#include "FlowKey.h"
#include "FlowRadar.h"
#include "HashPipe.h"
#include "Ideal.h"
#include "PacketParser.h"
#include "ResultMetrics.hpp"
#include "SketchLearn.h"
#include "UnivMon.h"

using namespace std::chrono_literals;

const std::string PCAP_FILE = "datasets/mawi_ether.pcap";

using FlowKeyType = TwoTuple;

const uint64_t SKETCH_MEMORY = 600 * 1024;

// const std::chrono::nanoseconds EPOCH_DURATION = 100ms;

// Heavy Hitter阈值百分比
const double HEAVY_HITTER_THRESHOLD_PERCENTAGE = 0.01;

namespace SketchParams {
const uint64_t CM_ROWS = 4;
const uint64_t CS_ROWS = 4;
const uint64_t ES_HEAVY_MEMORY = 300 * 1024;
const uint64_t ES_LAMBDA = 4;
const uint64_t ES_LIGHT_ROWS = 4;
const uint64_t UM_NUM_LAYERS = 4;
const double FR_BF_PERCENTAGE = 0.3;
const uint64_t FR_BF_NUM_HASHES = 3;
const uint64_t FR_CT_NUM_HASHES = 6;
}  // namespace SketchParams

template <typename FlowKeyType>
void process_epoch(
    const std::vector<typename PacketParser<FlowKeyType>::PacketRecordType>&
        packets,
    Ideal<FlowKeyType>& ideal,
    CountMin<FlowKeyType>& cm,
    CountSketch<FlowKeyType>& cs,
    ElasticSketch<FlowKeyType>& es,
    HashPipe<FlowKeyType>& hp,
    UnivMon<FlowKeyType>& um,
    SketchLearn<FlowKeyType>& sl,
    FlowRadar<FlowKeyType>& fr) {
    ideal.clear();
    cm.clear();
    cs.clear();
    es.clear();
    hp.clear();
    um.clear();
    sl.clear();
    fr.clear();

    // 处理每个数据包
    for (const auto& packet : packets) {
        ideal.update(packet.flow, 1);
        cm.update(packet.flow, 1);
        cs.update(packet.flow, 1);
        es.update(packet.flow, 1);
        hp.update(packet.flow, 1);
        um.update(packet.flow, 1);
        sl.update(packet.flow, 1);
        fr.update(packet.flow, 1);
    }
}

template <typename FlowKeyType>
void print_metrics_summary(
    const std::vector<std::string>& sketch_names,
    const std::vector<ResultMetrics<FlowKeyType>>& metrics_list) {
    std::cout << "\n";
    std::cout << "============================================================"
              << std::endl;
    std::cout << "                    Metrics Summary" << std::endl;
    std::cout << "============================================================"
              << std::endl;

    // 打印表头
    std::cout << std::fixed << std::setprecision(4);
    std::cout << std::left << std::setw(20) << "Sketch" << std::right
              << std::setw(12) << "Precision" << std::setw(12) << "Recall"
              << std::setw(12) << "F1-Score" << std::setw(12) << "Accuracy"
              << std::setw(12) << "ARE(%)" << std::setw(12) << "AAE"
              << std::setw(12) << "WMRE(%)" << std::endl;
    std::cout << "------------------------------------------------------------"
              << std::endl;

    // 打印每个sketch的指标
    for (size_t i = 0; i < sketch_names.size() && i < metrics_list.size();
         ++i) {
        const auto& m = metrics_list[i].get_heavy_hitter_metric();
        const auto& e = metrics_list[i].get_error_metric();

        std::cout << std::left << std::setw(20) << sketch_names[i] << std::right
                  << std::setw(12) << m.get_precision() * 100 << std::setw(12)
                  << m.get_recall() * 100 << std::setw(12) << m.get_f1_score()
                  << std::setw(12) << m.get_accuracy() * 100 << std::setw(12)
                  << e.are * 100 << std::setw(12) << e.aae << std::setw(12)
                  << e.wmre * 100 << std::endl;
    }

    std::cout << "============================================================"
              << std::endl;
}

int main(int argc, char* argv[]) {
    // Parse command line argument for epoch duration in milliseconds
    int epoch_ms = 100;  // default value
    if (argc > 1) {
        epoch_ms = std::atoi(argv[1]);
        if (epoch_ms <= 0) {
            std::cerr << "Error: Invalid epoch duration. Using default 100ms." << std::endl;
            epoch_ms = 100;
        }
    }
    const std::chrono::nanoseconds EPOCH_DURATION = std::chrono::milliseconds(epoch_ms);

    std::string pcap_file = PCAP_FILE;

    std::cout << "============================================================"
              << std::endl;
    std::cout << "          Sketch Performance Evaluation Tool" << std::endl;
    std::cout << "============================================================"
              << std::endl;
    std::cout << "PCAP File: " << pcap_file << std::endl;
    std::cout << "FlowKey Type: " << typeid(FlowKeyType).name() << std::endl;
    std::cout << "Sketch Memory: " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "Epoch Duration: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     EPOCH_DURATION)
                     .count()
              << " ms" << std::endl;
    std::cout << "Heavy Hitter Threshold: " << HEAVY_HITTER_THRESHOLD_PERCENTAGE
              << "% of total packets per epoch" << std::endl;
    std::cout << "\nSketch Parameters:" << std::endl;
    std::cout << "  CountMin:" << std::endl;
    std::cout << "    rows = " << SketchParams::CM_ROWS << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "  CountSketch:" << std::endl;
    std::cout << "    rows = " << SketchParams::CS_ROWS << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "  ElasticSketch:" << std::endl;
    std::cout << "    heavy_memory = " << SketchParams::ES_HEAVY_MEMORY / 1024
              << " KB" << std::endl;
    std::cout << "    lambda = " << SketchParams::ES_LAMBDA << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "    light_rows = 8 (default)" << std::endl;
    std::cout << "  HashPipe:" << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "    num_stages = 8 (default)" << std::endl;
    std::cout << "  UnivMon:" << std::endl;
    std::cout << "    num_layers = " << SketchParams::UM_NUM_LAYERS
              << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "    backend = CountSketch (default)" << std::endl;
    std::cout << "  SketchLearn:" << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "    num_rows = 1 (default)" << std::endl;
    std::cout << "    theta = 0.5 (default)" << std::endl;
    std::cout << "  FlowRadar:" << std::endl;
    std::cout << "    total_memory = " << SKETCH_MEMORY / 1024 << " KB"
              << std::endl;
    std::cout << "    bf_percentage = 0.3 (default)" << std::endl;
    std::cout << "    bf_num_hashes = 3 (default)" << std::endl;
    std::cout << "    ct_num_hashes = 3 (default)" << std::endl;
    std::cout << "============================================================"
              << std::endl;

    try {
        // 解析PCAP文件
        std::cout << "\n[1/4] Parsing PCAP file..." << std::endl;
        PacketParser<FlowKeyType> parser;
        auto epochs = parser.parse_pcap_with_epochs(pcap_file, EPOCH_DURATION);
        std::cout << "Found " << epochs.size() << " epochs" << std::endl;

        if (epochs.empty()) {
            std::cerr << "Error: No packets found in PCAP file" << std::endl;
            return 1;
        }

        // 初始化所有sketch
        std::cout << "\n[2/4] Initializing sketches..." << std::endl;
        Ideal<FlowKeyType> ideal;
        CountMin<FlowKeyType> cm(SketchParams::CM_ROWS, SKETCH_MEMORY);
        CountSketch<FlowKeyType> cs(SketchParams::CS_ROWS, SKETCH_MEMORY);
        ElasticSketch<FlowKeyType> es(SketchParams::ES_HEAVY_MEMORY,
                                      SketchParams::ES_LAMBDA, SKETCH_MEMORY,
                                      SketchParams::ES_LIGHT_ROWS);
        HashPipe<FlowKeyType> hp(SKETCH_MEMORY);
        UnivMon<FlowKeyType> um(SketchParams::UM_NUM_LAYERS, SKETCH_MEMORY);
        SketchLearn<FlowKeyType> sl(SKETCH_MEMORY);
        FlowRadar<FlowKeyType> fr(SKETCH_MEMORY, SketchParams::FR_BF_PERCENTAGE,
                                  SketchParams::FR_BF_NUM_HASHES,
                                  SketchParams::FR_CT_NUM_HASHES);

        std::vector<std::string> sketch_names = {
            "CountMin", "CountSketch", "ElasticSketch", "HashPipe",
            "UnivMon",  "SketchLearn", "FlowRadar"};

        // 存储所有epoch的metrics
        std::vector<std::vector<ResultMetrics<FlowKeyType>>> all_epoch_metrics(
            sketch_names.size());

        // 处理每个epoch
        std::cout << "\n[3/4] Processing epochs..." << std::endl;
        for (size_t epoch_idx = 0; epoch_idx < epochs.size(); ++epoch_idx) {
            std::cout << "Processing epoch " << (epoch_idx + 1) << "/"
                      << epochs.size() << " (" << epochs[epoch_idx].size()
                      << " packets)...\n"
                      << std::flush;

            // 处理当前epoch
            process_epoch(epochs[epoch_idx], ideal, cm, cs, es, hp, um, sl, fr);

            // 计算epoch的总包数
            uint64_t total_packets = 0;
            auto ideal_data = ideal.get_raw_data();
            for (const auto& pair : ideal_data) {
                total_packets += pair.second;
            }

            // 根据百分比计算实际阈值
            uint32_t threshold = static_cast<uint32_t>(
                total_packets * HEAVY_HITTER_THRESHOLD_PERCENTAGE / 100.0);
            if (threshold == 0 && total_packets > 0) {
                threshold = 1;  // 至少为1
            }

            // 计算metrics
            all_epoch_metrics[0].emplace_back(ideal, cm, threshold);
            all_epoch_metrics[1].emplace_back(ideal, cs, threshold);
            all_epoch_metrics[2].emplace_back(ideal, es, threshold);
            all_epoch_metrics[3].emplace_back(ideal, hp, threshold);
            all_epoch_metrics[4].emplace_back(ideal, um, threshold);
            all_epoch_metrics[5].emplace_back(ideal, sl, threshold);
            all_epoch_metrics[6].emplace_back(ideal, fr, threshold);
        }

        // 计算平均metrics并打印总结
        std::cout
            << "\n============================================================"
            << std::endl;
        std::cout << "              Average Metrics Across All Epochs"
                  << std::endl;
        std::cout
            << "============================================================"
            << std::endl;

        // 计算所有epoch的平均值
        std::vector<std::map<std::string, double>> avg_metrics_data;
        for (size_t sketch_idx = 0; sketch_idx < sketch_names.size();
             ++sketch_idx) {
            if (all_epoch_metrics[sketch_idx].empty()) {
                continue;
            }

            // 聚合所有epoch的metrics
            std::map<std::string, double> sums;
            size_t num_epochs = all_epoch_metrics[sketch_idx].size();

            // 初始化sums
            for (const auto& pair :
                 all_epoch_metrics[sketch_idx][0].get_all_metrics()) {
                sums[pair.first] = 0.0;
            }

            // 累加所有epoch的值
            for (const auto& metrics : all_epoch_metrics[sketch_idx]) {
                auto epoch_metrics = metrics.get_all_metrics();
                for (auto& pair : sums) {
                    sums[pair.first] += epoch_metrics[pair.first];
                }
            }

            // 计算平均值
            std::map<std::string, double> avg;
            for (const auto& pair : sums) {
                avg[pair.first] = pair.second / num_epochs;
            }
            avg_metrics_data.push_back(avg);
        }

        // 打印平均metrics总结
        std::cout << std::fixed << std::setprecision(4);
        std::cout << std::left << std::setw(20) << "Sketch" << std::right
                  << std::setw(12) << "Precision" << std::setw(12) << "Recall"
                  << std::setw(12) << "F1-Score" << std::setw(12) << "Accuracy"
                  << std::setw(12) << "ARE(%)" << std::setw(12) << "AAE"
                  << std::setw(12) << "WMRE(%)" << std::endl;
        std::cout
            << "------------------------------------------------------------"
            << std::endl;

        for (size_t i = 0;
             i < sketch_names.size() && i < avg_metrics_data.size(); ++i) {
            const auto& avg = avg_metrics_data[i];
            double precision = avg.at("precision");
            double recall = avg.at("recall");
            double f1 = 2.0 * precision * recall / (precision + recall + 1e-10);
            double accuracy = avg.at("accuracy");

            std::cout << std::left << std::setw(20) << sketch_names[i]
                      << std::right << std::setw(12) << precision * 100
                      << std::setw(12) << recall * 100 << std::setw(12) << f1
                      << std::setw(12) << accuracy * 100 << std::setw(12)
                      << avg.at("are") * 100 << std::setw(12) << avg.at("aae")
                      << std::setw(12) << avg.at("wmre") * 100 << std::endl;
        }

        std::cout
            << "============================================================"
            << std::endl;

        std::cout << "\nEvaluation completed successfully!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
