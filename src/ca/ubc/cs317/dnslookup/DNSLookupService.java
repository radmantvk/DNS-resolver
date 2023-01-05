package ca.ubc.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

import java.nio.ByteBuffer;

public class DNSLookupService {

    private static boolean p1Flag = false; // isolating part 1
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static DNSCache cache = DNSCache.getInstance();
    private static Set<ResourceRecord> inetResponses = new LinkedHashSet<>();
    private static String nextCNAME = "";
    private static RecordType ogType = RecordType.OTHER;
    private static int counter = 0;
    private static int tooManyQueries = 0;


    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length == 2 && args[1].equals("-p1")) {
            p1Flag = true;
        } else if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            DNSQueryHandler.openSocket();
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    boolean verboseTracing = false;
                    if (commandArgs[1].equalsIgnoreCase("on")) {
                        verboseTracing = true;
                        DNSQueryHandler.setVerboseTracing(true);
                    }
                    else if (commandArgs[1].equalsIgnoreCase("off")) {
                        DNSQueryHandler.setVerboseTracing(false);
                    }
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
            }

        } while (true);

        DNSQueryHandler.closeSocket();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        inetResponses.clear();
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the results for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        if (p1Flag) { // For isolating part 1 testing only
            retrieveResultsFromServer(node, rootServer);
            return Collections.emptySet();
        } else if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        
        // Sets the initial value for the Type Code of the query 
        if (ogType.getCode() == 0) { // if type being looked up is not set to anything, set it to the node type
            ogType = node.getType();
        }
        if (tooManyQueries > 15) {
            return inetResponses;
        }
        // Calls the first retrieveResults
        retrieveResultsFromServer(node, rootServer);
        if (!inetResponses.isEmpty()) {
            filterType();
            return inetResponses;
        }
        if (tooManyQueries > 15) {
            return inetResponses;
        }
        if (!nextCNAME.equals(node.getHostName())) {
            DNSNode newNode = new DNSNode(nextCNAME, node.getType());
            return getResults(newNode, ++indirectionLevel);
        }  
        return Collections.emptySet();
    }
    // Helper function to filter out undesirable types, ones not associated with first type
    private static void filterType() {
        Iterator<ResourceRecord> it = inetResponses.iterator();
        while (it.hasNext()) {
            ResourceRecord next = it.next();
            if (ogType.getCode() != next.getType().getCode()) {
                inetResponses.remove(next);
            }
        }
    }
        

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] message = new byte[512]; // query is no longer than 512 bytes
        try {
            DNSServerResponse serverResponse = DNSQueryHandler.buildAndSendQuery(message, server, node);
            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(serverResponse.getTransactionID(),
                    serverResponse.getResponse(),
                    cache);
            if (nameservers == null) nameservers = Collections.emptySet();

            if (p1Flag) return; // For testing part 1 only

            queryNextLevel(node, nameservers);

        } catch (IOException | NullPointerException ignored){}
    }
 
private static final int INET=0; 
private static final int NSINET=0;
private static final int CNAMEINET=0;
    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param nameservers List of name servers returned from the previous level to query the next level.
     */
    
    private static void queryNextLevel(DNSNode node, Set<ResourceRecord> nameservers) {
        // Checks to make sure we have not had too many queries 

        Iterator<ResourceRecord> iterator = nameservers.iterator();
        Set<ResourceRecord> actualResults = new LinkedHashSet<>(); 
        List<String> nsNames = new ArrayList<>();
        List<String> nsNamesWithINET = new ArrayList<>();
        Map<String, InetAddress> nsMap = new HashMap<>();
        nextCNAME = node.getHostName();     // lastCName = OGDomainName 
        
        // This while loop processes all of the RRs from a query based on case. 
        while(iterator.hasNext()) {
            ResourceRecord rr = iterator.next();

            String hostName =rr.getHostName();
            switch(rr.getType()) {
                case A:
                case AAAA: 
                        InetAddress inet = rr.getInetResult();
                        if (rr.getType() == RecordType.AAAA) {
                            String temp = inet.toString();
                            int len = temp.length();
                            temp = temp.substring(1, len);
                            String[] items = temp.split("\\:");
                            // // List<String> listItems = new ArrayList<>();
                            
                            // List<Integer> intList = new ArrayList<>();
                            byte[] result = new byte[20];
                            ByteBuffer output = ByteBuffer.wrap(result);
                            for (int i = 0; i < items.length; i++) {
                                output.put(items[i].getBytes());
                            }
                            try {
                                inet = InetAddress.getByAddress(result);
                            } catch (IOException e) {
                        }
                            System.out.println("INET ~>" + inet.getHostAddress());

                        }
                        
                    
                    if (hostName.equals(nextCNAME)) {     // stores the actual node's INETc
                        actualResults.add(rr);
                    } else if (nsNames.indexOf(hostName) != -1 && !nsMap.containsKey(hostName)) { // if ns exists in the list, stores the NS's INET
                        nsMap.put(hostName, inet);  
                        nsNamesWithINET.add(hostName);
                    } else if (nsNames.indexOf(hostName) != -1) {
                        if (ogType == rr.getType()) {
                            nsMap.put(hostName, inet); 
                        }
                    } else {
                    }
                    break;
                case NS:
                    nsNames.add(rr.getTextResult());
                    break;
                case CNAME:
                    if (hostName.equals(nextCNAME)) {
                        nextCNAME = rr.getTextResult();
                    }
                    break;
                case SOA:
                    break;
                default:
                    if (ogType == rr.getType()) {
                        actualResults.add(rr);
                    }
                    break;
            }
        }
        
        // case 1: Either CNAME or OGname has INET
        if (!actualResults.isEmpty()) {  // either a CNAME or the OGName has corresponded to some INET
            inetResponses = actualResults;
            return;
        } 
        
        if (!node.getHostName().equals(nextCNAME)) {
            return;
        }
        
        // case 2: NS has INET
        else if (!nsMap.isEmpty()) { // NS has INET: call retrieve on NS
            for (int i=0; i < nsMap.size(); i++) {
                if (!node.getHostName().equals(nextCNAME)) {
                    return;
                }
                retrieveResultsFromServer(node, nsMap.get(nsNamesWithINET.get(0)));
                if (!inetResponses.isEmpty()) {  
                    return;
                }
            }  
            return;
        }
        
        // removing NS names with INET
        for (int i = 0; i < nsNamesWithINET.size(); i++) {
            nsNames.remove(nsNamesWithINET.get(i));
        }   
        
        // Case 3: NS names without INET
        if (!nsNames.isEmpty()) { // NS has no INET: call retrieve on NS
            //for (int i=0; i < nsNames.size(); i++) {
                
                DNSNode nsNode = new DNSNode(nsNames.get(0), RecordType.A);
if (!node.getHostName().equals(nextCNAME)) {
                    }
                retrieveResultsFromServer(nsNode, rootServer);
                nsNames.remove(0);
                if (!inetResponses.isEmpty()) {
                    actualResults = new HashSet<>(inetResponses);
                    inetResponses.clear();
                    Iterator<ResourceRecord> it = actualResults.iterator();
                    while (it.hasNext()) {
                        retrieveResultsFromServer(node, it.next().getInetResult());
                        if (counter > 0) {
                        }
                        if (!inetResponses.isEmpty()) {
                            break;
                        }
                    }
                } else {
                    return;
                } 
            };

        // case 4: CNAME no INET ~> should reach here be handled in getResults()
    }
 

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30.30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30.30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
