/*
 * Yet Another UserAgent Analyzer
 * Copyright (C) 2013-2018 Niels Basjes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.basjes.parse.useragent.utils;

import nl.basjes.parse.useragent.Version;
import nl.basjes.parse.useragent.analyze.InvalidParserConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.SequenceNode;

import java.util.List;

import static nl.basjes.parse.useragent.utils.YamlUtils.fail;
import static nl.basjes.parse.useragent.utils.YamlUtils.getExactlyOneNodeTuple;
import static nl.basjes.parse.useragent.utils.YamlUtils.getKeyAsString;
import static nl.basjes.parse.useragent.utils.YamlUtils.getValueAsSequenceNode;
import static nl.basjes.parse.useragent.utils.YamlUtils.getValueAsString;

public final class YauaaVersion {

    private static final Logger LOG = LoggerFactory.getLogger(YauaaVersion.class);

    private YauaaVersion() {
    }

    public static void logVersion(String... extraLines) {
        String[] lines = {
            "For more information: https://github.com/nielsbasjes/yauaa",
            "Copyright (C) 2013-2018 Niels Basjes - License Apache 2.0"
        };
        String version = getVersion();
        int width = version.length();
        for (String line : lines) {
            width = Math.max(width, line.length());
        }
        for (String line : extraLines) {
            width = Math.max(width, line.length());
        }

        LOG.info("");
        LOG.info("/-{}-\\", padding('-', width));
        logLine(version, width);
        LOG.info("+-{}-+", padding('-', width));
        for (String line : lines) {
            logLine(line, width);
        }
        if (extraLines.length > 0) {
            LOG.info("+-{}-+", padding('-', width));
            for (String line : extraLines) {
                logLine(line, width);
            }
        }

        LOG.info("\\-{}-/", padding('-', width));
        LOG.info("");
    }

    private static String padding(char letter, int count) {
        StringBuilder sb = new StringBuilder(128);
        for (int i = 0; i < count; i++) {
            sb.append(letter);
        }
        return sb.toString();
    }

    private static void logLine(String line, int width) {
        LOG.info("| {}{} |", line, padding(' ', width - line.length()));
    }

    public static String getVersion() {
        return getVersion(Version.getProjectVersion(), Version.getGitCommitIdDescribeShort(), Version.getBuildTimestamp());
    }

    public static String getVersion(String projectVersion, String gitCommitIdDescribeShort, String buildTimestamp) {
        return "Yauaa " + projectVersion + " (" + gitCommitIdDescribeShort + " @ " + buildTimestamp + ")";
    }


    public static void assertSameVersion(NodeTuple versionNodeTuple, String filename) {
        // Check the version information from the Yaml files
        SequenceNode versionNode = getValueAsSequenceNode(versionNodeTuple, filename);
        String gitCommitIdDescribeShort = null;
        String buildTimestamp = null;
        String projectVersion = null;

        List<Node> versionList = versionNode.getValue();
        for (Node versionEntry : versionList) {
            if (!(versionEntry instanceof MappingNode)) {
                fail(versionEntry, filename, "The entry MUST be a mapping");
            }
            NodeTuple entry = getExactlyOneNodeTuple((MappingNode) versionEntry, filename);
            String key = getKeyAsString(entry, filename);
            String value = getValueAsString(entry, filename);
            switch (key) {
                case "git_commit_id_describe_short":
                    gitCommitIdDescribeShort = value;
                    break;
                case "build_timestamp":
                    buildTimestamp = value;
                    break;
                case "project_version":
                    projectVersion = value;
                    break;
                default:
                    throw new InvalidParserConfigurationException(
                        "Yaml config.(" + filename + ":" + versionNode.getStartMark().getLine() + "): " +
                            "Found unexpected config entry: " + key + ", allowed are " +
                            "'git_commit_id_describe_short', 'build_timestamp' and 'project_version'");
            }
        }
        assertSameVersion(gitCommitIdDescribeShort, buildTimestamp, projectVersion);
    }

    public static void assertSameVersion(String gitCommitIdDescribeShort, String buildTimestamp, String projectVersion) {
        String libraryGitCommitIdDescribeShort = Version.getGitCommitIdDescribeShort();
        String libraryBuildTimestamp = Version.getBuildTimestamp();
        String libraryProjectVersion = Version.getProjectVersion();
        if (libraryGitCommitIdDescribeShort.equals(gitCommitIdDescribeShort) &&
            libraryBuildTimestamp.equals(buildTimestamp) &&
            libraryProjectVersion.equals(projectVersion)) {
            return;
        }

        String libraryVersion = getVersion(libraryProjectVersion, libraryGitCommitIdDescribeShort, libraryBuildTimestamp);
        String rulesVersion = getVersion(projectVersion, gitCommitIdDescribeShort, buildTimestamp);

        LOG.error("===============================================");
        LOG.error("==========        FATAL ERROR       ===========");
        LOG.error("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv");
        LOG.error("");
        LOG.error("Two different Yauaa versions have been loaded:");
        LOG.error("Runtime Library: {}", libraryVersion);
        LOG.error("Rule sets      : {}", rulesVersion);
        LOG.error("");
        LOG.error("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
        LOG.error("===============================================");

        throw new InvalidParserConfigurationException("Two different Yauaa versions have been loaded: \n" +
            "Runtime Library: " + libraryVersion + "\n" +
            "Rule sets      : " + rulesVersion + "\n");
    }

}
