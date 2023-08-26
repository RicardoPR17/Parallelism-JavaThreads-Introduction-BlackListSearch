/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.threads;

/**
 *
 * @author hcadavid
 */
public class CountThread extends Thread {
    int A;
    int B;

    public CountThread(int a, int b) {
        this.A = a;
        this.B = b;
    }

    public void run() {
        for (int i = A; i <= B; i++) {
            System.out.println(i);
        }
    }
}
