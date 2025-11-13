#!/bin/bash

# ============================================================================
# 编译脚本 - 编译 main.cpp 并链接已编译的库文件
# ============================================================================

set -e  # 遇到错误立即退出

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

clear

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Building Single File with Medivh ${NC}"
echo -e "${GREEN}========================================${NC}"

# 检查必要的目录
if [ ! -d "SketchLib" ]; then
    echo -e "${RED}Error: SketchLib directory not found${NC}"
    exit 1
fi

if [ ! -d "PcapPlusPlus-25.05" ]; then
    echo -e "${RED}Error: PcapPlusPlus-25.05 directory not found${NC}"
    exit 1
fi

# 创建build目录
BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

# 查找库文件
SKETCHLIB_LIB=""
PCPP_LIBS=()

# 查找 SketchLib 库
SKETCHLIB_LIB="$PROJECT_ROOT/build/SketchLib/libSketchLib.a"

if [ ! -f "$SKETCHLIB_LIB" ]; then
    echo -e "${RED}Error: SketchLib library not found. Please build the project first using CMake.${NC}"
    echo -e "${YELLOW}Expected location:${NC}"
    echo -e "  - build/SketchLib/libSketchLib.a"
    exit 1
fi

# 查找 PcapPlusPlus 库
PCPP_PACKET_LIB="$PROJECT_ROOT/build/PcapPlusPlus-25.05/Packet++/libPacket++.a"
PCPP_COMMON_LIB="$PROJECT_ROOT/build/PcapPlusPlus-25.05/Common++/libCommon++.a"

if [ ! -f "$PCPP_PACKET_LIB" ]; then
    echo -e "${RED}Error: PcapPlusPlus Packet++ library not found. Please build the project first using CMake.${NC}"
    echo -e "${YELLOW}Expected location:${NC}"
    echo -e "  - build/PcapPlusPlus-25.05/Packet++/libPacket++.a"
    exit 1
fi

if [ ! -f "$PCPP_COMMON_LIB" ]; then
    echo -e "${RED}Error: PcapPlusPlus Common++ library not found. Please build the project first using CMake.${NC}"
    echo -e "${YELLOW}Expected location:${NC}"
    echo -e "  - build/PcapPlusPlus-25.05/Common++/libCommon++.a"
    exit 1
fi

PCPP_LIBS=("$PCPP_PACKET_LIB" "$PCPP_COMMON_LIB")

echo -e "${GREEN}Found libraries:${NC}"
echo -e "  SketchLib: ${SKETCHLIB_LIB}"
echo -e "  PcapPlusPlus Packet++: ${PCPP_PACKET_LIB}"
echo -e "  PcapPlusPlus Common++: ${PCPP_COMMON_LIB}"

# 设置编译参数
CXX="g++"
CXXFLAGS="-std=c++14 -O3 -Wall -Wextra"
# CXXFLAGS="-g"
INCLUDES=(
    "-I$PROJECT_ROOT/include"
    "-I$PROJECT_ROOT/SketchLib/include"
    "-I$PROJECT_ROOT/SketchLib/third_party"
    "-I$PROJECT_ROOT/PcapPlusPlus-25.05/header"
    "-I$PROJECT_ROOT/PcapPlusPlus-25.05/Common++/header"
    "-I$PROJECT_ROOT/PcapPlusPlus-25.05/Packet++/header"
)

# 源文件
SOURCES=(
    "main.cpp"
    "src/PacketParser.cpp"
)

# 输出文件
OUTPUT="$BUILD_DIR/main"

echo -e "${GREEN}Compiling...${NC}"

# 编译命令
"$CXX" $CXXFLAGS \
    "${INCLUDES[@]}" \
    "${SOURCES[@]}" \
    "$SKETCHLIB_LIB" \
    "${PCPP_LIBS[@]}" \
    -lpthread \
    -o "$OUTPUT"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Build successful!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "Output: ${GREEN}$OUTPUT${NC}"
    echo -e "\nRun with: ${GREEN}$OUTPUT${NC}"
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  Build failed!${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
