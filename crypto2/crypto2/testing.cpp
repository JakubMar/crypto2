/** 
 * @file main.cpp
 * @author Martin Ukrop
 * @licence MIT Licence
 */



// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Initial testing", "[always true]") {
    CHECK(1 == 1);
    
}
