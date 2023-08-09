// See https://aka.ms/new-console-template for more information

using System.Text;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

Console.WriteLine("Initializing");
var module = ModuleDefinition.FromFile("Devlooped.SponsorLink.dll");

// internal class 6FA47342-3716-4274-AF01-7A37793E0E97
var stringsType = module.LookupMember<TypeDefinition>(0x02000048);

// internal static 6FA47342-3716-4274-AF01-7A37793E0E97.2 3;
var stringsByteArrayField = module.LookupMember<FieldDefinition>(0x0400008F);
var stringsByteArray = stringsByteArrayField.FieldRva!.WriteIntoArray();

// static 6FA47342-3716-4274-AF01-7A37793E0E97()
for (int i = 0; i < stringsByteArray.Length; i++)
    stringsByteArray[i] = (byte)(stringsByteArray[i] ^ i ^ 170);

var decryptionMethods = stringsType.Methods.Where(m =>
    m is { IsStatic: true, Parameters.Count: 0 } && m.Signature!.ReturnType == module.CorLibTypeFactory.String);

Console.WriteLine("Cleaning");
var decryptedStrings = new Dictionary<MethodDefinition, string>();
foreach (var method in decryptionMethods)
{
    var instructions = method.CilMethodBody!.Instructions;
    var byteArrayIndex = instructions[7];
    if (!byteArrayIndex.IsLdcI4())
        throw new Exception("Expected ldc.i4 on instruction 7, got " + byteArrayIndex);
    
    var byteArrayCount = instructions[8];
    if (!byteArrayCount.IsLdcI4())
        throw new Exception("Expected ldc.i4 on instruction 8, got " + byteArrayCount);

    decryptedStrings[method] = Encoding.UTF8.GetString(stringsByteArray,
        byteArrayIndex.GetLdcI4Constant(), byteArrayCount.GetLdcI4Constant());
}

foreach (var type in module.GetAllTypes())
foreach (var method in type.Methods)
foreach (var instruction in method.CilMethodBody!.Instructions)
    if (instruction.OpCode.Code is CilCode.Call && instruction.Operand is MethodDefinition methodCall &&
        decryptedStrings.TryGetValue(methodCall, out var decryptedString))
        instruction.ReplaceWith(CilOpCodes.Ldstr, decryptedString);

Console.WriteLine("Done");
module.Write("Devlooped.SponsorLink-cleaned.dll");
