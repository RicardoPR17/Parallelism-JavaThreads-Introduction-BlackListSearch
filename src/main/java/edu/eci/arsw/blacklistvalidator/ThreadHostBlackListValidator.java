package edu.eci.arsw.blacklistvalidator;

import java.util.LinkedList;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

/**
 * @author Avatar
 */
public class ThreadHostBlackListValidator extends Thread {

    /**
     * Flag that indicates the minimun number of appearances of the suspicious host
     * in the servers
     */
    private static final int BLACK_LIST_ALARM_COUNT = 5;
    /**
     * The IP of the suspicious host to check
     */
    private String ip;
    /**
     * Lower range of the servers to check
     */
    private int inf_limit;
    /**
     * Higher range of the servers to check
     */
    private int sup_limit;
    /**
     * Number of appearances of the suspicious host in the servers
     */
    private int ocurrences;
    /**
     * Number of servers checked in the range
     */
    private int checkedListsCount;
    /**
     * List with the server's number where the suspicious host was found
     */
    private LinkedList<Integer> threadBlackList = new LinkedList<>();

    /**
     * Constructor of the thread to check the suspicious host
     * 
     * @param ip        Suspicious host's ip to check
     * @param inf_limit Lower range of the servers to check
     * @param sup_limit Higher range of the servers to check
     */
    public ThreadHostBlackListValidator(String ip, int inf_limit, int sup_limit) {
        this.ip = ip;
        this.inf_limit = inf_limit;
        this.sup_limit = sup_limit;
    }

    /**
     * Check if the suspicious host is registered on the servers, only check the
     * servers in the given range. Count the number of servers checked, the number
     * of appearances of the IP and register the servers were the IP was found.
     */
    @Override
    public void run() {

        int ocurrencesCount = 0;

        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        checkedListsCount = 0;

        for (int i = inf_limit; i < sup_limit && ocurrencesCount < BLACK_LIST_ALARM_COUNT; i++) {
            checkedListsCount++;

            if (skds.isInBlackListServer(i, ip)) {

                threadBlackList.add(i);

                ocurrencesCount++;
            }
        }

        this.ocurrences = ocurrencesCount;
    }

    /**
     * Get the number of ocurrences of the suspiciuos host
     * 
     * @return The number of appearances
     */
    public int getOcurrences() {
        return this.ocurrences;
    }

    /**
     * Get the list with the servers where the suspicious host was found
     * 
     * @return A list of integers that represent the servers where the suspicious
     *         host was found
     */
    public LinkedList<Integer> getThreadBlackList() {
        return this.threadBlackList;
    }

    /**
     * Get the count of the servers that were checked
     * 
     * @return An integer with the count of the servers checked in the given range
     */
    public int getCheckedList() {
        return checkedListsCount;
    }

}
