#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <random>

std::string loadFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

void saveFile(const std::string& path, const std::string& content)
{
    std::ofstream file(path, std::ios::binary);
    if (file)
        file << content;
}

std::string toHex(const std::string& input)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');

    for (unsigned char c : input)
        out << std::setw(2) << static_cast<int>(c);

    return out.str();
}

std::string generateKey()
{
    static const char charset[] = "abcdef0123456789";
    static std::mt19937 rng{ std::random_device{}() };

    int length = 6 + (rng() % 4);
    std::string key;
    key.reserve(length);

    for (int i = 0; i < length; ++i)
        key += charset[rng() % 16];

    return key;
}

std::string obfuscateLua(
    const std::string& code,
    std::vector<std::pair<std::string, std::string>>& table
)
{
    std::string result;
    std::string buffer;
    bool inString = false;

    for (size_t i = 0; i < code.size(); ++i)
    {
        char c = code[i];

        if (c == '"' && (i == 0 || code[i - 1] != '\\'))
        {
            if (inString)
            {
                std::string key = generateKey();
                table.emplace_back(key, toHex(buffer));
                result += "_T[__k(\"" + key + "\")]";
                buffer.clear();
                inString = false;
            }
            else
            {
                inString = true;
            }
        }
        else if (inString)
        {
            buffer += c;
        }
        else
        {
            result += c;
        }
    }

    return result;
}

std::string buildLua(
    const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& table
)
{
    std::string tableInit;

    for (const auto& it : table)
        tableInit += "_T[__k(\"" + it.first + "\")] = __d(\"" + it.second + "\")\n";

    return
        R"(local function __d(h)
    return (h:gsub("..", function(c)
        return string.char(tonumber(c, 16))
    end))
end

local function __k(h)
    return __d(h)
end

return (function(...)
    local _T = {}
)"
+ tableInit +
R"(
)"
+ body +
R"(
end)(...)
)";
}

int main()
{
    std::string inputPath;
    std::cout << "Lua file path: ";
    std::getline(std::cin, inputPath);

    std::string source = loadFile(inputPath);
    if (source.empty())
    {
        std::cout << "Error: cannot read file\n";
        return 1;
    }

    std::vector<std::pair<std::string, std::string>> table;
    std::string obfuscated = obfuscateLua(source, table);
    std::string finalLua = buildLua(obfuscated, table);

    std::string output = inputPath;
    size_t dot = output.find_last_of('.');
    if (dot != std::string::npos)
        output = output.substr(0, dot);

    output += "_obfuscated.lua";

    saveFile(output, finalLua);
    std::cout << "SUCCESS -> " << output << "\n";
    return 0;
}