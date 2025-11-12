#ifndef RESULT_METRICS_HPP
#define RESULT_METRICS_HPP

#include <iomanip>
#include <iostream>
#include <map>
#include "Ideal.h"
#include "Sketch.h"

template <typename FlowKeyType, typename SFINAE = RequireFlowKey<FlowKeyType>>
class ResultMetrics {
   public:
    struct ErrorMetric {
        double are = 0.0;   // Average Relative Error
        double aae = 0.0;   // Average Absolute Error
        double wmre = 0.0;  // Weighted Mean Relative Error
    };

    struct HeavyHitterMetric {
        uint32_t tp = 0;     // True Positives
        uint32_t tn = 0;     // True Negatives
        uint32_t fp = 0;     // False Positives
        uint32_t fn = 0;     // False Negatives
        uint32_t threshold;  // Heavy Hitter阈值

        double get_precision() const {
            double total_positive = tp + fp;
            return total_positive > 0 ? tp / total_positive : 0.0;
        }

        double get_recall() const {
            double total_actual_positive = tp + fn;
            return total_actual_positive > 0 ? tp / total_actual_positive : 0.0;
        }

        double get_f1_score() const {
            double precision = get_precision();
            double recall = get_recall();
            return (precision + recall) > 0
                       ? 2.0 * precision * recall / (precision + recall)
                       : 0.0;
        }

        double get_accuracy() const {
            double total = tp + tn + fp + fn;
            return total > 0 ? (tp + tn) / total : 0.0;
        }

        double get_tpr() const { return get_recall(); }

        double get_fpr() const {
            double total_actual_negative = tn + fp;
            return total_actual_negative > 0 ? fp / total_actual_negative : 0.0;
        }
    };

    ResultMetrics(const Ideal<FlowKeyType>& ideal,
                  const Sketch<FlowKeyType>& sketch,
                  uint32_t hh_threshold) {
        evaluate(ideal, sketch, hh_threshold);
    }

    const ErrorMetric& get_error_metric() const { return error_metric_; }

    const HeavyHitterMetric& get_heavy_hitter_metric() const {
        return heavy_hitter_metric_;
    }

    // 拿到所有结果的 map
    std::map<std::string, double> get_all_metrics() const {
        std::map<std::string, double> metrics;

        metrics["are"] = error_metric_.are;
        metrics["aae"] = error_metric_.aae;
        metrics["wmre"] = error_metric_.wmre;

        metrics["tp"] = static_cast<double>(heavy_hitter_metric_.tp);
        metrics["tn"] = static_cast<double>(heavy_hitter_metric_.tn);
        metrics["fp"] = static_cast<double>(heavy_hitter_metric_.fp);
        metrics["fn"] = static_cast<double>(heavy_hitter_metric_.fn);
        metrics["precision"] = heavy_hitter_metric_.get_precision();
        metrics["recall"] = heavy_hitter_metric_.get_recall();
        metrics["f1_score"] = heavy_hitter_metric_.get_f1_score();
        metrics["accuracy"] = heavy_hitter_metric_.get_accuracy();
        metrics["tpr"] = heavy_hitter_metric_.get_tpr();
        metrics["fpr"] = heavy_hitter_metric_.get_fpr();
        metrics["threshold"] =
            static_cast<double>(heavy_hitter_metric_.threshold);

        return metrics;
    }

    void print_metrics() const {
        std::cout << "\n=====================================" << std::endl;
        std::cout << "Heavy Hitter阈值: " << heavy_hitter_metric_.threshold
                  << std::endl;

        std::cout << std::fixed << std::setprecision(4);
        std::cout << "  " << std::left << std::setw(25)
                  << "真正例 (TP):" << std::right << std::setw(12)
                  << heavy_hitter_metric_.tp << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "真负例 (TN):" << std::right << std::setw(12)
                  << heavy_hitter_metric_.tn << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "假正例 (FP):" << std::right << std::setw(12)
                  << heavy_hitter_metric_.fp << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "假负例 (FN):" << std::right << std::setw(12)
                  << heavy_hitter_metric_.fn << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "精度 (Precision):" << std::right << std::setw(11)
                  << heavy_hitter_metric_.get_precision() * 100 << "%"
                  << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "召回率 (Recall):" << std::right << std::setw(11)
                  << heavy_hitter_metric_.get_recall() * 100 << "%"
                  << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "F1分数 (F1 Score):" << std::right << std::setw(12)
                  << heavy_hitter_metric_.get_f1_score() << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "准确率 (Accuracy):" << std::right << std::setw(11)
                  << heavy_hitter_metric_.get_accuracy() * 100 << "%"
                  << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "真正率 (TPR):" << std::right << std::setw(11)
                  << heavy_hitter_metric_.get_tpr() * 100 << "%" << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "假正率 (FPR):" << std::right << std::setw(11)
                  << heavy_hitter_metric_.get_fpr() * 100 << "%" << std::endl;

        std::cout << "\n频率估计误差指标:" << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "平均相对误差 (ARE):" << std::right << std::setw(11)
                  << error_metric_.are * 100 << "%" << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "平均绝对误差 (AAE):" << std::right << std::setw(12)
                  << error_metric_.aae << std::endl;
        std::cout << "  " << std::left << std::setw(25)
                  << "加权平均相对误差 (WMRE):" << std::right << std::setw(11)
                  << error_metric_.wmre * 100 << "%" << std::endl;

        std::cout << "=====================================\n" << std::endl;
    }

   private:
    ErrorMetric error_metric_;
    HeavyHitterMetric heavy_hitter_metric_;

    void evaluate(const Ideal<FlowKeyType>& ideal,
                  const Sketch<FlowKeyType>& sketch,
                  uint32_t threshold) {
        heavy_hitter_metric_.threshold = threshold;

        auto ideal_data = const_cast<Ideal<FlowKeyType>&>(ideal).get_raw_data();

        if (ideal_data.empty()) {
            return;
        }

        uint64_t total_packets = 0;
        double sum_absolute_error = 0.0;
        double sum_relative_error = 0.0;
        double sum_weighted_relative_error = 0.0;
        uint32_t total_flows = 0;

        // 遍历全部流
        for (const auto& pair : ideal_data) {
            const auto& flow = pair.first;
            uint64_t true_count = pair.second;
            uint64_t estimated_count =
                const_cast<Sketch<FlowKeyType>&>(sketch).query(flow);

            // 更新误差统计
            double absolute_error =
                std::abs(static_cast<double>(true_count) -
                         static_cast<double>(estimated_count));
            sum_absolute_error += absolute_error;

            if (true_count > 0) {
                double relative_error =
                    absolute_error / static_cast<double>(true_count);
                sum_relative_error += relative_error;
                sum_weighted_relative_error +=
                    relative_error * static_cast<double>(true_count);
            }

            total_flows++;
            total_packets += true_count;

            // 更新Heavy Hitter混淆矩阵
            bool is_heavy_ideal = true_count >= threshold;
            bool is_heavy_estimated = estimated_count >= threshold;

            if (is_heavy_ideal && is_heavy_estimated) {
                heavy_hitter_metric_.tp++;
            } else if (!is_heavy_ideal && !is_heavy_estimated) {
                heavy_hitter_metric_.tn++;
            } else if (!is_heavy_ideal && is_heavy_estimated) {
                heavy_hitter_metric_.fp++;
            } else {
                heavy_hitter_metric_.fn++;
            }
        }

        if (total_flows > 0) {
            error_metric_.are = sum_relative_error / total_flows;
            error_metric_.aae = sum_absolute_error / total_flows;
        }

        if (total_packets > 0) {
            error_metric_.wmre = sum_weighted_relative_error / total_packets;
        }
    }
};

#endif  // RESULT_METRICS_HPP
