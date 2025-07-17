/*You've been hired by a small music media start-up. Their successful podcast and newsletter have led to a spike in
traffic, initially bringing a welcome increase in subscriptions. However, concerns are growing
that some traffic may be non-human, and the servers are becoming overwhelmed.
Parts of the website go down every few days due to the sheer volume of traffic.
With an engineering team of just three people, this downtime is severely impacting their productivity.

**Your task is to solve this issue:**
Using a provided set of logs you must identify the problem and determine the best way to handle the increased traffic.

FOR QUICK LEARNING
Log Format: IP - Country Code - Timestamp - HTTP Method & URL - Status Code - User Browser/Bot - Original Source - Response Size
Status codes -> 200 (success), 404 (not found), 500 (server error), 302 (temporarily moved) */

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class LogAnalyser {

    // Static class to hold log components
    static class LogEntry {
        String ip;
        String country;
        String method;
        String url;
        int status;
        String userAgent;
        String timestamp;
    }

    public static void main(String[] args) {
        String log_file = "sample-log.log"; // Sample log filepath
        List<LogEntry> logs = new ArrayList<>(); // Holds logs

        // Data structures to dictate suspicious IP addresses (counting IP and requests)
        Map<String, Integer> ipCount = new HashMap<>();
        Map<String, Integer> suspiciousIPs = new HashMap<>();

        // Regex to parse individual logs
        String regex = "(\\S+) - (\\S+) - \\[(.*?)\\] \"(\\S+) " +
                "(.*?) HTTP/\\d\\.\\d\" (\\d{3}) \\d+ \"[^\"]*\" \"([^\"]*)\" \\d+";
        Pattern pattern = Pattern.compile(regex);

        try (BufferedReader br = new BufferedReader(new FileReader(log_file))) {
            String line;
            while ((line = br.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    LogEntry entry = new LogEntry();
                    entry.ip = matcher.group(1);
                    entry.country = matcher.group(2);
                    entry.timestamp = matcher.group(3);
                    entry.method = matcher.group(4);
                    entry.url = matcher.group(5);
                    entry.status = Integer.parseInt(matcher.group(6));
                    entry.userAgent = matcher.group(7);
                    logs.add(entry);

                    // Counts requests per IP Address
                    ipCount.put(entry.ip, ipCount.getOrDefault(entry.ip, 0) + 1);

                    // Detect suspicious HTTP methods
                    if (entry.method.equals("PUT")) {
                        suspiciousIPs.put(entry.ip, suspiciousIPs.getOrDefault(entry.ip, 0) + 1);
                    }
                    // Detect multiple login attempts
                    if (entry.url.contains("login")) {
                        suspiciousIPs.put(entry.ip, suspiciousIPs.getOrDefault(entry.ip, 0) + 1);
                    }
                }
            }

            // Output Summary
            System.out.println("===== LOG ANALYSIS =====");
            System.out.println("Total Sampled Logs: " + logs.size());

            // Shows IPs with high request counts from ascending to descending order.
            System.out.println("\nTop IPs by Request Count:");
            ipCount.entrySet().stream()
                    .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                    .limit(10)
                    .forEach(e -> System.out.println(e.getKey() + " -> " + e.getValue() + " requests"));

            // Highlights suspicious IPs based on attempted activities above.
            System.out.println("\nSuspicious IPs:");
            suspiciousIPs.forEach((ip, count) -> {
                System.out.println(ip + " -> " + count + " suspicious actions");
            });

        } catch (IOException e) {
            System.out.println("An error has occurred reading log file");
        }
    }
}

