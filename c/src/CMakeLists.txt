cmake_minimum_required (VERSION 2.6)

# add_subdirectory(libzrtpcpp)
# add_subdirectory(libzrtpcpp/crypto)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

set(skein_src 
    skein_block.c
    skein.c
    skeinMacApi.c
    )

set(threefish_src
    threefishApi.c
    threefish256Block.c
    threefish512Block.c
    threefish1024Block.c
    )
set(s3f_src ${skein_src} ${threefish_src})

add_library(skein3fish SHARED ${s3f_src})
set_target_properties(skein3fish PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(skein3fish ${LIBS})

# add_subdirectory(include)

# src_distribution_init()
# add_src_dist_files(${s3f_src} )
# add_src_dist_dirs(libzrtpcpp)

install(TARGETS skein3fish DESTINATION ${LIBDIRNAME})

