#include "BddTargetStderrErrorHandler.h"
#include "CppUTest/TestHarness.h"

// clang-format off
TEST_GROUP(BddTargetStderrErrorHandler)
{
    void teardown() override
    {
        BddTargetStderrErrorHandler_SetByName("errors-fatal", "1");
    }
};

// clang-format on

TEST(BddTargetStderrErrorHandler, SetByNameTakesErrorsFatalOff)
{
    CHECK_TRUE(BddTargetStderrErrorHandler_SetByName("errors-fatal", "0"));
}

TEST(BddTargetStderrErrorHandler, SetByNameTakesErrorsFatalOn)
{
    CHECK_TRUE(BddTargetStderrErrorHandler_SetByName("errors-fatal", "1"));
}

TEST(BddTargetStderrErrorHandler, SetByNameRejectsAValueThatIsNeither)
{
    CHECK_FALSE(BddTargetStderrErrorHandler_SetByName("errors-fatal", "yes"));
}

TEST(BddTargetStderrErrorHandler, SetByNameRejectsANameItDoesNotOwn)
{
    CHECK_FALSE(BddTargetStderrErrorHandler_SetByName("tls-ca", "ca"));
}
