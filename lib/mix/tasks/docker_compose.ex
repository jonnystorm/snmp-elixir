defmodule Mix.Tasks.DockerCompose do
  use Mix.Task

  @docker_compose_exec "docker-compose"

  @shortdoc "Start up #{@docker_compose_exec} used for testing"
  def run(_) do
    case System.find_executable(@docker_compose_exec) do
      nil ->
        raise "#{@docker_compose_exec} not found on this machine, please install docker and@docker_compose_execso that these tests can run"

      _path ->
        File.cd(File.cwd!())
        System.cmd(@docker_compose_exec, ["up", "-d"])
    end
  end
end
