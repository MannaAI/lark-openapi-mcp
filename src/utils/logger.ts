import fs from 'fs';
import path from 'path';
import { ENV_PATHS } from './constants';
import { currentVersion } from './version';

export enum LogLevel {
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
}

// A deployed server has no way to pass --debug, and the default WARN level
// discards every OAuth breadcrumb in this codebase (they are all logger.info),
// so a client failing at discovery or auth leaves the logs completely empty.
const levelFromEnv = (): LogLevel | undefined => {
  const name = process.env.LOG_LEVEL?.trim().toUpperCase();
  return name && name in LogLevel ? (LogLevel[name as keyof typeof LogLevel] as LogLevel) : undefined;
};

export class Logger {
  private level: LogLevel = levelFromEnv() ?? LogLevel.WARN;

  static logFilesToKeep = 7;

  static logFilePrefix = 'lark-mcp-';

  constructor() {
    this.initLogFile();
    this.cleanHistoryLogFile();
  }

  get logFileName() {
    return `${Logger.logFilePrefix}${new Date().toISOString().split('T')[0]}.log`;
  }

  initLogFile = () => {
    if (!fs.existsSync(ENV_PATHS.log)) {
      fs.mkdirSync(ENV_PATHS.log, { recursive: true });
    }
  };

  cleanHistoryLogFile = () => {
    try {
      // clean old log files, 7 days ago
      const logFiles = fs
        .readdirSync(ENV_PATHS.log)
        .filter((file) => file.startsWith(Logger.logFilePrefix) && file.endsWith('.log'));
      const logFilesToDelete = logFiles.filter((file) => {
        const fileDate = file.split('-')[1].split('.')[0];
        const fileDateObj = new Date(fileDate);
        return fileDateObj < new Date(Date.now() - Logger.logFilesToKeep * 24 * 60 * 60 * 1000);
      });
      for (const file of logFilesToDelete) {
        try {
          fs.unlinkSync(path.join(ENV_PATHS.log, file));
        } catch (error) {
          console.error(`Failed to delete log file: ${error}`);
        }
      }
    } catch (error) {
      console.error(`Failed to clean history log file: ${error}`);
    }
  };

  setLevel = (level: LogLevel) => {
    this.level = level;
  };

  log = (message: string) => {
    try {
      fs.appendFileSync(
        path.join(ENV_PATHS.log, this.logFileName),
        `[${new Date().toISOString()}] [${currentVersion}] [${process.pid}] ${message}\n`,
      );
    } catch (error) {
      console.error(`Failed to write log: ${error} ${message}`);
    }
  };

  // stderr, not stdout: under the stdio transport stdout carries the MCP protocol
  // itself, so writing logs there corrupts the stream. warn/error already went to
  // the console; info/debug went only to a log file, which inside a container is
  // a file nobody can read -- so an OAuth flow failing left no visible trace.
  // Both are still gated by the level, which defaults to WARN.
  debug = (message: string) => {
    if (this.level < LogLevel.DEBUG) {
      return;
    }
    console.error(`[DEBUG] ${message}`);
    this.log(`[DEBUG] ${message}`);
  };

  info = (message: string) => {
    if (this.level < LogLevel.INFO) {
      return;
    }
    console.error(`[INFO] ${message}`);
    this.log(`[INFO] ${message}`);
  };

  warn = (message: string) => {
    if (this.level < LogLevel.WARN) {
      return;
    }
    console.error(`[WARN] ${message}`);
    this.log(`[WARN] ${message}`);
  };

  error = (message: string) => {
    if (this.level < LogLevel.ERROR) {
      return;
    }
    console.error(`[ERROR] ${message}`);
    this.log(`[ERROR]  ${message}`);
  };
}

export const logger = new Logger();
