import unittest

from core.rls_review import review


class RLSReviewTests(unittest.TestCase):
    def test_explicit_disable(self):
        result = review("-- synthetic migration\nALTER TABLE public.demo DISABLE ROW LEVEL SECURITY;")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["line"], 2)
        self.assertEqual(result["findings"][0]["status"], "REVIEW_REQUIRED")

    def test_enabled(self):
        self.assertEqual(review("ALTER TABLE public.demo ENABLE ROW LEVEL SECURITY;")["findings"], [])

    def test_reenabled(self):
        sql = "ALTER TABLE demo DISABLE ROW LEVEL SECURITY; ALTER TABLE demo ENABLE ROW LEVEL SECURITY;"
        self.assertEqual(review(sql)["findings"], [])

    def test_comments_and_literals(self):
        sql = """-- ALTER TABLE demo DISABLE ROW LEVEL SECURITY;
        /* outer /* nested */ ALTER TABLE demo DISABLE ROW LEVEL SECURITY; */
        SELECT 'a; ALTER TABLE demo DISABLE ROW LEVEL SECURITY;';
        DO $$ BEGIN RAISE NOTICE 'ALTER TABLE demo DISABLE ROW LEVEL SECURITY;'; END $$;
        """
        self.assertEqual(review(sql)["findings"], [])

    def test_quoted_and_case(self):
        result = review('ALTER TABLE IF EXISTS ONLY "Demo"."Table" DISABLE ROW LEVEL SECURITY;')
        self.assertEqual(result["findings"][0]["table"], '"Demo" . "Table"')

    def test_incomplete_comment(self):
        with self.assertRaises(ValueError):
            review("/* unfinished")

    def test_dynamic_sql_not_claimed(self):
        self.assertEqual(review("DO $body$ BEGIN EXECUTE 'ALTER TABLE demo DISABLE ROW LEVEL SECURITY'; END $body$;")["findings"], [])

    def test_oversize(self):
        with self.assertRaises(ValueError):
            review(" " * (1024 * 1024 + 1))

    def test_ambiguous_literal(self):
        with self.assertRaises(ValueError):
            review("SELECT 'a" + chr(92) + "b';")


if __name__ == "__main__":
    unittest.main()
