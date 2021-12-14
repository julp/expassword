ExPassword.Test.Set.algorithms()
|> Enum.each(&ExPassword.Registry.register_algorithm/1)

ExUnit.start()
