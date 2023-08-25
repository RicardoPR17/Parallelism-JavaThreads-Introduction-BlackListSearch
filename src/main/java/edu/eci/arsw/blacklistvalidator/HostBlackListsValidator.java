/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT = 5;

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case. The search
     * is divided by the number of threads, each of them search in a range of the
     * servers. When all the threads complete his part, the next step is validate if
     * the given host's IP address is turstworthy or not. The search is not
     * exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as NOT
     * Trustworthy, and the list of the five blacklists returned.
     * 
     * @param ipaddress suspicious host's IP address.
     * @param n         number of threads
     * @return Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int n) {

        LinkedList<Integer> blackListOcurrences = new LinkedList<>();

        int ocurrencesCount = 0;

        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount = 0;

        int inf_limit = 1;

        int sup_limit = skds.getRegisteredServersCount();

        ArrayList<Thread> threadsList = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            ThreadHostBlackListValidator thread = new ThreadHostBlackListValidator(ipaddress,
                    inf_limit + (i * (sup_limit - inf_limit) / n), inf_limit + ((i + 1) * (sup_limit - inf_limit) / n));

            threadsList.add(thread);
        }

        for (Thread j : threadsList) {
            j.start();
        }

        for (Thread k : threadsList) {
            try {
                k.join();
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
            }
        }

        for (Thread l : threadsList) {
            ThreadHostBlackListValidator threadAux = (ThreadHostBlackListValidator) l;
            for (Integer m : threadAux.getThreadBlackList()) {
                blackListOcurrences.add(m);
            }
            ocurrencesCount += threadAux.getOcurrences();
            checkedListsCount += threadAux.getCheckedList();
        }

        if (ocurrencesCount >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ipaddress);
        } else {
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}",
                new Object[] { checkedListsCount, skds.getRegisteredServersCount() });

        return blackListOcurrences;
    }

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());

}
