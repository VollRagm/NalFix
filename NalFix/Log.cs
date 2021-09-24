using System;

public static class Log
{
    public static void Critical(object value)
    {
        Color(ConsoleColor.Yellow);
        Console.WriteLine("[!] " + value.ToString());
        Color();
    }

    public static void Info(object value)
    {
        Color(ConsoleColor.Cyan);
        Console.WriteLine("[+] " + value.ToString());
    }

    public static bool QueryYesNo(string question)
    {
        var input = QueryString(question);
        if (input.ToLower().StartsWith("y")) return true;
        else return false;
    }

    public static string QueryString(string question)
    {
        Color(ConsoleColor.Yellow);
        Console.Write("[?] " + question);
        Color();
        return Console.ReadLine();
    }

    public static void Info(object value, ConsoleColor color)
    {
        Color(color);
        Console.WriteLine("[+] " + value.ToString());
    }

    public static void Error(object value)
    {
        Color(ConsoleColor.Red);
        Console.WriteLine("[-] " + value.ToString());
        Color();
    }

    public static void Fatal(object value)
    {
        Error(value);
        Console.ReadLine();
        Environment.Exit(0);
    }

    private static void Color(ConsoleColor color = ConsoleColor.White)
    {
        Console.ForegroundColor = color;
    }
}
