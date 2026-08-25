<?php
// Deliberately flawed: exists so PHP scanners have something to report.
// Reads an undefined variable, calls an unknown method, and interpolates
// input into a shell command.
namespace Example;

class App
{
    public function run(string $name): string
    {
        $result = shell_exec("echo " . $name);
        echo $undefinedVariable;
        return $result;
    }

    public function broken(): int
    {
        return $this->doesNotExist();
    }
}
