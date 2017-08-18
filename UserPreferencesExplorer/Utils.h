#pragma once

#include <string>

namespace Utils
{
    /// <summary>
    /// Reads all bytes from the specified path.
    /// </summary>
    /// <param name="path">Path to the file to read.</param>
    /// <returns>Container of sequential bytes or empty container on error.</returns>
    std::vector<uint8_t> ReadAllBytes(const std::string &path);

    /// <summary>
    /// Gets the machine GUID.
    /// </summary>
    /// <returns>The machine GUID on success or an empty string on failure.</returns>
    std::string GetPathToUserPreferencesBag();

    /// <summary>
    /// Gets the path to the user's UserPreferences.bag.
    /// </summary>
    /// <returns>Path to the user's UserPreferences.bag.</returns>
    std::string GetMachineGuid();
};
