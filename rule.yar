rule ExampleRule
{
    strings:
        $exampleString = "malicious"
    condition:
        $exampleString
}