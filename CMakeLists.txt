cmake_minimum_required(VERSION 3.5)

project(triller)

set (triller_flow_sou
    src/triller/main_triller.cpp
    src/triller/triller_flow.cpp
    src/triller/H12_flow.cpp
    src/fingerprint/smp_fp.cpp
)

add_executable(ShortVideoIdentification ${triller_flow_sou})
target_include_directories(ShortVideoIdentification PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ShortVideoIdentification ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a )
target_link_libraries(ShortVideoIdentification ${PROJECT_SOURCE_DIR}/lib/win/libFlow2SE.a )
target_link_libraries(ShortVideoIdentification ${PROJECT_SOURCE_DIR}/lib/win/libPcapSE.a )
target_link_libraries(ShortVideoIdentification ${PROJECT_SOURCE_DIR}/lib/win/libPacketSE.a )
target_link_libraries(ShortVideoIdentification ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a )
target_link_libraries(ShortVideoIdentification ${PROJECT_SOURCE_DIR}/lib/win/libTlsFragSE.a )
