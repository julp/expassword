defmodule ExPassword.Bcrypt.VerifyTest do
  use ExUnit.Case

  describe "ExPassword.Bcrypt.verify?/2" do
    test "ensures only password matches to a bcrypt hash" do
      assert true == ExPassword.Bcrypt.verify?("", "$2y$04$35MAXYSjPyfzANk1PE4jpe6BFtSTc3m125J3MsT9LfMAmKsxH.DIu")
      assert true == ExPassword.Bcrypt.verify?("", "$2y$10$3gnIByDAmymRzloXsEjBCO5XqO0eahvErvNAG7jXr0SA4jm7g6QIO")

      assert true == ExPassword.Bcrypt.verify?("password", "$2y$04$5LEzpJFJbsVLiAPtunma.eWxP0D4CvNd5fw4cV9wT3cSCO.5oG4iO")
      assert true == ExPassword.Bcrypt.verify?("password", "$2y$10$26108htOOGxDvB0pR82L8eYluJgCNCCJr1opIwzM0Te3zJmp29Rmy")

      assert false == ExPassword.Bcrypt.verify?("", "$2y$04$5LEzpJFJbsVLiAPtunma.eWxP0D4CvNd5fw4cV9wT3cSCO.5oG4iO")
      assert false == ExPassword.Bcrypt.verify?("", "$2y$10$26108htOOGxDvB0pR82L8eYluJgCNCCJr1opIwzM0Te3zJmp29Rmy")

      if Code.ensure_loaded?(ExPassword.Bcrypt.Base) do
        assert false == ExPassword.Bcrypt.verify?("password\x00", "$2y$04$GQ8fkszdqnITr1NAbV373egWUmXr7pSPDCV7OaJ1r0ftWsM5ALnOW")
        assert false == ExPassword.Bcrypt.verify?("password\x00", "$2y$10$JDQ/0aKg9CgK5vsN37CaQeTSYtg9Y1Ob2Mv7QDozKIGuNQrzHE6uW")
      end

      assert true == ExPassword.Bcrypt.verify?("password", "$2y$04$GQ8fkszdqnITr1NAbV373egWUmXr7pSPDCV7OaJ1r0ftWsM5ALnOW")
      assert true == ExPassword.Bcrypt.verify?("password", "$2y$10$JDQ/0aKg9CgK5vsN37CaQeTSYtg9Y1Ob2Mv7QDozKIGuNQrzHE6uW")
    end
  end
end
