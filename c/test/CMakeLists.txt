
# set the following source property when testin katScan, remove otherwise
#set_property(SOURCE katScan.c PROPERTY COMPILE_DEFINITIONS KAT_SCAN_TESTING)
#add_executable(katScan katScan.c)

add_executable(threefishTest threefishTest.c)
target_link_libraries(threefishTest skein3fish)

add_executable(skeinTest skeinTest.c katScan.c)
target_link_libraries(skeinTest skein3fish)

add_executable(skeinBench skeinBench.c)
target_link_libraries(skeinBench skein3fish)

########### install files ###############
# None

########### source distribution ########
# include(SourceDistribution)
# src_distribution_init()
# add_src_dist_files(zrtptestMulti.cpp zrtptest.cpp)
