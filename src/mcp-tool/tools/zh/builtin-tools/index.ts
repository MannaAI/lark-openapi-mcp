import { docxBuiltinToolName, docxBuiltinTools } from './docx/builtin';
import { driveBuiltinToolName, driveBuiltinTools } from '../../en/builtin-tools/drive/doc-wiki-search';
import { imBuiltinToolName, imBuiltinTools } from './im/buildin';
import { sheetsBuiltinToolName, sheetsBuiltinTools } from '../../en/builtin-tools/sheets/values';

export const BuiltinTools = [...docxBuiltinTools, ...driveBuiltinTools, ...imBuiltinTools, ...sheetsBuiltinTools];

export type BuiltinToolName = docxBuiltinToolName | driveBuiltinToolName | imBuiltinToolName | sheetsBuiltinToolName;
