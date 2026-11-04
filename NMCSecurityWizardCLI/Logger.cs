using System;
using System.IO;

namespace NMCSecurityWizardCLI;

internal class Logger
{
	private string ResultLogFilename;

	private string ErrorLogFilename;

	public Logger()
	{
		ResultLogFilename = "result.log";
		ErrorLogFilename = "error.log";
	}

	public Logger(string sUpdateFile, string sErrorFile)
	{
		ResultLogFilename = sUpdateFile;
		ErrorLogFilename = sErrorFile;
	}

	public void AddEvent(Globals._LogStorage logStorage, string format, params object[] args)
	{
		string text = string.Format(format, args);
		Console.WriteLine("[*] " + text);
		if (logStorage == Globals._LogStorage.LogError || logStorage == Globals._LogStorage.LogResultError)
		{
			File.AppendAllText(ErrorLogFilename, "[" + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss") + "] " + text + Environment.NewLine);
		}
		if (logStorage == Globals._LogStorage.LogResult || logStorage == Globals._LogStorage.LogResultError)
		{
			File.AppendAllText(ResultLogFilename, "[" + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss") + "] " + text + Environment.NewLine);
		}
	}
}
