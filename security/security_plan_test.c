// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

static void security_plan_finish_result_test(struct kunit *test)
{
	int first;

	first = security_plan_merge_finish_result(-EIO, -EIO, -EIO);
	KUNIT_EXPECT_EQ(test, first, -EIO);
	first = security_plan_merge_finish_result(first, -EIO, 0);
	KUNIT_EXPECT_EQ(test, first, -EIO);
	first = security_plan_merge_finish_result(first, -EIO, -EPROTO);
	KUNIT_EXPECT_EQ(test, first, -EPROTO);
	first = security_plan_merge_finish_result(first, -EIO, -ESTALE);
	KUNIT_EXPECT_EQ(test, first, -EPROTO);

	first = security_plan_merge_finish_result(0, 0, -ENOMEM);
	KUNIT_EXPECT_EQ(test, first, -ENOMEM);
	first = security_plan_merge_finish_result(first, 0, -EPROTO);
	KUNIT_EXPECT_EQ(test, first, -ENOMEM);
}

static void security_plan_participant_bitmap_test(struct kunit *test)
{
	struct security_inode_create_plan create = {};
	struct security_inode_setxattr_plan setxattr = {};
	unsigned int last = MAX_LSM_COUNT - 1;

	KUNIT_EXPECT_FALSE(test, test_bit(0, create.prepared_lsms));
	KUNIT_EXPECT_FALSE(test, test_bit(last, create.prepared_lsms));
	__set_bit(0, create.prepared_lsms);
	__set_bit(last, create.prepared_lsms);
	KUNIT_EXPECT_TRUE(test, test_bit(0, create.prepared_lsms));
	KUNIT_EXPECT_TRUE(test, test_bit(last, create.prepared_lsms));
	KUNIT_EXPECT_FALSE(test, test_bit(0, setxattr.prepared_lsms));
	__set_bit(last, setxattr.prepared_lsms);
	KUNIT_EXPECT_TRUE(test, test_bit(last, setxattr.prepared_lsms));
}

static void security_plan_error_pointer_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		security_inode_create_plan_finish(ERR_PTR(-ENOMEM), 0, NULL),
		-ENOMEM);
	KUNIT_EXPECT_EQ(test,
		security_inode_create_plan_finish(ERR_PTR(-ENOMEM), -EIO, NULL),
		-EIO);
	KUNIT_EXPECT_EQ(test,
		security_inode_setxattr_plan_finish(ERR_PTR(-ENOMEM), 0),
		-ENOMEM);
	KUNIT_EXPECT_EQ(test,
		security_inode_setxattr_plan_finish(ERR_PTR(-ENOMEM), -EIO),
		-EIO);
}

static struct kunit_case security_plan_test_cases[] = {
	KUNIT_CASE(security_plan_finish_result_test),
	KUNIT_CASE(security_plan_participant_bitmap_test),
	KUNIT_CASE(security_plan_error_pointer_test),
	{}
};

static struct kunit_suite security_plan_test_suite = {
	.name = "security-plan-protocol",
	.test_cases = security_plan_test_cases,
};

kunit_test_suite(security_plan_test_suite);
