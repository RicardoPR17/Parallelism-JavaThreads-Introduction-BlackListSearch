package edu.eci.arsw.blacklistvalidator;

import java.util.LinkedList;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

public class ThreadHostBlackListValidator extends Thread {

    private static final int BLACK_LIST_ALARM_COUNT = 5;
    private String ip;
    private int inf_limit;
    private int sup_limit;
    private int ocurrences;
    private int checkedListsCount;
    private LinkedList<Integer> threadBlackList = new LinkedList<>();

    public ThreadHostBlackListValidator(String ip, int inf_limit, int sup_limit) {
        this.ip = ip;
        this.inf_limit = inf_limit;
        this.sup_limit = sup_limit;
    }

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

    public int getOcurrences() {
        return this.ocurrences;
    }

    public LinkedList<Integer> getThreadBlackList() {
        return this.threadBlackList;
    }

    public int getCheckedList() {
        return checkedListsCount;
    }

}
