import { docxBuiltinToolName, docxBuiltinTools } from './docx/builtin';
import { driveBuiltinToolName, driveBuiltinTools } from '../../en/builtin-tools/drive/doc-wiki-search';
import { imBuiltinToolName, imBuiltinTools } from './im/buildin';

export const BuiltinTools = [...docxBuiltinTools, ...driveBuiltinTools, ...imBuiltinTools];

export type BuiltinToolName = docxBuiltinToolName | driveBuiltinToolName | imBuiltinToolName;
