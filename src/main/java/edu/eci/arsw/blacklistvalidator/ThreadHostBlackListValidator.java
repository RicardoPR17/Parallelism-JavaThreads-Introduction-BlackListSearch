package edu.eci.arsw.blacklistvalidator;

import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

public class ThreadHostBlackListValidator extends Thread {

    private static final int BLACK_LIST_ALARM_COUNT = 5;
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    private String ip;
    private int inf_limit;
    private int sup_limit;
    private int ocurrences;
    private LinkedList threadBlackList;

    public ThreadHostBlackListValidator(String ip, int inf_limit, int sup_limit) {
        this.ip = ip;
        this.inf_limit = inf_limit;
        this.sup_limit = sup_limit;
    }

    public void run() {
        LinkedList<Integer> blackListOcurrences = new LinkedList<>();

        int ocurrencesCount = 0;

        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount = 0;

        for (int i = inf_limit; i < sup_limit && ocurrencesCount < BLACK_LIST_ALARM_COUNT; i++) {
            checkedListsCount++;

            if (skds.isInBlackListServer(i, ip)) {

                blackListOcurrences.add(i);

                ocurrencesCount++;
            }
        }

        if (ocurrencesCount >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ip);
        } else {
            skds.reportAsTrustworthy(ip);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}",
                new Object[] { checkedListsCount, skds.getRegisteredServersCount() });

        this.threadBlackList = blackListOcurrences;
        this.ocurrences = ocurrencesCount;
    }

    public int getOcurrences() {
        return this.ocurrences;
    }

    public LinkedList getThreatBlackList() {
        return this.threadBlackList;
    }

}
