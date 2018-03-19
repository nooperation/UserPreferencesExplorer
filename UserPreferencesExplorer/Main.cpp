#include <string>
#include <iostream>
#include <boost/program_options.hpp>

#include "../UserPreferences.Shared/Common.h"
#include "../UserPreferences.Shared/Encryption.h"

int main(int argc, char* argv[])
{
    namespace po = boost::program_options;

    try
    {
        auto arg_salt = po::value<std::string>()->default_value(UserPreferences::Common::GetDefaultSalt(), "");
        auto arg_guid = po::value<std::string>()->default_value(UserPreferences::Common::GetMachineGuid(), "");
        auto arg_path = po::value<std::string>()->default_value(UserPreferences::Common::GetPathToUserPreferencesBag(), "");

        auto commandline_descriptions = po::options_description("Arguments");
        commandline_descriptions.add_options()
            ("help", "Help")
            ("salt", arg_salt, "Salt used for key generation.")
            ("guid", arg_guid, "GUID used for key generation.")
            ("path", arg_path, "Path to the UserPreferences.bag to decrypt.");

        auto parsed_options = po::parse_command_line(argc, argv, commandline_descriptions);
        po::variables_map vm;
        po::store(parsed_options, vm);
        po::notify(vm);

        if (vm.count("help"))
        {
            std::cout << commandline_descriptions << std::endl;
            return EXIT_SUCCESS;
        }

        auto path = vm["path"].as<std::string>();
        auto guid = vm["guid"].as<std::string>();
        auto salt = vm["salt"].as<std::string>();

        auto ciphertext = UserPreferences::Common::ReadAllBytes(vm["path"].as<std::string>());
        auto plaintext = UserPreferences::Encryption::DecryptData(ciphertext, guid, salt);
        auto plaintext_string = std::string(plaintext.begin(), plaintext.end());

        std::cout << plaintext_string << std::endl;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Failed to decrypt user preferences: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
