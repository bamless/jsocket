add_library(jsocket SHARED socket.c)
target_link_libraries(jsocket PUBLIC jstar::jstar)
set_target_properties(jsocket PROPERTIES OUTPUT_NAME "socket")
target_compile_options(jsocket
    PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W3>
        $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra>
        $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra>
)

add_custom_command(TARGET jsocket POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:jsocket> ${PROJECT_SOURCE_DIR}/src
)

if(LTO)
    set_target_properties(jsocket PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif(LTO)

include(GNUInstallDirs)
install(TARGETS jsocket LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/jstar)
install(FILES socket.jsr DESTINATION ${CMAKE_INSTALL_LIBDIR}/jstar)
