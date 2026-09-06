import { docxBuiltinToolName, docxBuiltinTools } from './docx/builtin';
import { driveBuiltinToolName, driveBuiltinTools } from './drive/doc-wiki-search';
import { imBuiltinToolName, imBuiltinTools } from './im/buildin';
import { sheetsBuiltinToolName, sheetsBuiltinTools } from './sheets/values';

export const BuiltinTools = [...docxBuiltinTools, ...driveBuiltinTools, ...imBuiltinTools, ...sheetsBuiltinTools];

export type BuiltinToolName = docxBuiltinToolName | driveBuiltinToolName | imBuiltinToolName | sheetsBuiltinToolName;
